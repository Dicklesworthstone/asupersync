#![no_main]

use libfuzzer_sys::fuzz_target;
use arbitrary::Arbitrary;

/// Tests RFC 7540 §6.10 CONTINUATION frame ordering requirements.
///
/// CONTINUATION frames MUST directly follow HEADERS/PUSH_PROMISE/CONTINUATION.
/// Any other frame type between HEADERS and CONTINUATION is a PROTOCOL_ERROR.
///
/// Invalid sequence: HEADERS(END_HEADERS=0) → PRIORITY → CONTINUATION
/// Valid sequence:   HEADERS(END_HEADERS=0) → CONTINUATION(END_HEADERS=1)

#[derive(Arbitrary, Debug, Clone)]
struct ContinuationOrderingInput {
    stream_id: u32,
    headers_flags: u8,
    priority_weight: u8,
    priority_dependency: u32,
    continuation_flags: u8,
    payload_size: u8,  // Keep small to avoid OOM
    sequence_variant: u8,  // Controls test scenario
}

/// HTTP/2 frame types per RFC 7540 §6
#[derive(Debug, Clone, Copy, PartialEq)]
enum FrameType {
    Data = 0x0,
    Headers = 0x1,
    Priority = 0x2,
    RstStream = 0x3,
    Settings = 0x4,
    PushPromise = 0x5,
    Ping = 0x6,
    GoAway = 0x7,
    WindowUpdate = 0x8,
    Continuation = 0x9,
}

/// Mock HTTP/2 frame for testing
#[derive(Debug, Clone)]
struct Http2Frame {
    frame_type: FrameType,
    flags: u8,
    stream_id: u32,
    payload: Vec<u8>,
}

impl Http2Frame {
    fn new_headers(stream_id: u32, flags: u8, payload: Vec<u8>) -> Self {
        Self {
            frame_type: FrameType::Headers,
            flags,
            stream_id,
            payload,
        }
    }

    fn new_priority(stream_id: u32, exclusive: bool, dependency: u32, weight: u8) -> Self {
        let mut payload = Vec::new();

        // PRIORITY frame payload (5 bytes):
        // Bit 0: E (Exclusive) flag
        // Bits 1-31: Stream Dependency (31 bits)
        // Bits 32-39: Weight (8 bits)
        let dependency_with_exclusive = if exclusive {
            dependency | 0x80000000
        } else {
            dependency & 0x7FFFFFFF
        };

        payload.extend_from_slice(&dependency_with_exclusive.to_be_bytes());
        payload.push(weight);

        Self {
            frame_type: FrameType::Priority,
            flags: 0,  // PRIORITY frames have no flags
            stream_id,
            payload,
        }
    }

    fn new_continuation(stream_id: u32, flags: u8, payload: Vec<u8>) -> Self {
        Self {
            frame_type: FrameType::Continuation,
            flags,
            stream_id,
            payload,
        }
    }

    fn new_data(stream_id: u32, flags: u8, payload: Vec<u8>) -> Self {
        Self {
            frame_type: FrameType::Data,
            flags,
            stream_id,
            payload,
        }
    }

    fn end_headers(&self) -> bool {
        self.flags & 0x4 != 0  // END_HEADERS flag
    }

    fn end_stream(&self) -> bool {
        self.flags & 0x1 != 0  // END_STREAM flag
    }
}

/// State tracking for HEADERS/CONTINUATION sequences
#[derive(Debug, Clone, PartialEq)]
enum HeaderBlockState {
    Idle,
    HeadersReceived(u32),  // stream_id of ongoing header block
    ExpectingContinuation(u32),  // stream_id expecting CONTINUATION
}

/// Mock connection for testing CONTINUATION frame ordering
struct MockContinuationConnection {
    header_block_state: HeaderBlockState,
    processed_frames: usize,
    protocol_errors: Vec<ContinuationError>,
    valid_sequences: usize,
}

#[derive(Debug, Clone, PartialEq)]
enum ContinuationError {
    ContinuationAfterNonHeaders {
        expected_stream: u32,
        interrupting_frame: FrameType,
        interrupting_stream: u32,
    },
    ContinuationOnWrongStream {
        expected_stream: u32,
        actual_stream: u32,
    },
    UnexpectedContinuation {
        stream_id: u32,
    },
    HeadersNotCompleted {
        stream_id: u32,
    },
}

impl MockContinuationConnection {
    fn new() -> Self {
        Self {
            header_block_state: HeaderBlockState::Idle,
            processed_frames: 0,
            protocol_errors: Vec::new(),
            valid_sequences: 0,
        }
    }

    fn process_frame(&mut self, frame: &Http2Frame) -> bool {
        self.processed_frames += 1;

        match frame.frame_type {
            FrameType::Headers => self.handle_headers_frame(frame),
            FrameType::Continuation => self.handle_continuation_frame(frame),
            FrameType::Priority => self.handle_priority_frame(frame),
            FrameType::Data | FrameType::RstStream | FrameType::Settings
            | FrameType::PushPromise | FrameType::Ping | FrameType::GoAway
            | FrameType::WindowUpdate => self.handle_other_frame(frame),
        }
    }

    fn handle_headers_frame(&mut self, frame: &Http2Frame) -> bool {
        match &self.header_block_state {
            HeaderBlockState::ExpectingContinuation(expected_stream) => {
                // Another HEADERS while expecting CONTINUATION on different stream
                self.protocol_errors.push(ContinuationError::HeadersNotCompleted {
                    stream_id: *expected_stream,
                });
                false
            }
            _ => {
                if frame.end_headers() {
                    // Complete header block in one frame
                    self.header_block_state = HeaderBlockState::Idle;
                    self.valid_sequences += 1;
                    true
                } else {
                    // Partial header block - expecting CONTINUATION
                    self.header_block_state = HeaderBlockState::ExpectingContinuation(frame.stream_id);
                    true
                }
            }
        }
    }

    fn handle_continuation_frame(&mut self, frame: &Http2Frame) -> bool {
        match &self.header_block_state {
            HeaderBlockState::ExpectingContinuation(expected_stream) => {
                if frame.stream_id == *expected_stream {
                    if frame.end_headers() {
                        // Header block completed
                        self.header_block_state = HeaderBlockState::Idle;
                        self.valid_sequences += 1;
                    }
                    // Still expecting more CONTINUATION frames if not END_HEADERS
                    true
                } else {
                    // CONTINUATION on wrong stream
                    self.protocol_errors.push(ContinuationError::ContinuationOnWrongStream {
                        expected_stream: *expected_stream,
                        actual_stream: frame.stream_id,
                    });
                    false
                }
            }
            _ => {
                // CONTINUATION without preceding HEADERS
                self.protocol_errors.push(ContinuationError::UnexpectedContinuation {
                    stream_id: frame.stream_id,
                });
                false
            }
        }
    }

    fn handle_priority_frame(&mut self, frame: &Http2Frame) -> bool {
        match &self.header_block_state {
            HeaderBlockState::ExpectingContinuation(expected_stream) => {
                // RFC 7540 §6.10: CONTINUATION must immediately follow HEADERS
                // PRIORITY frame between HEADERS and CONTINUATION is PROTOCOL_ERROR
                self.protocol_errors.push(ContinuationError::ContinuationAfterNonHeaders {
                    expected_stream: *expected_stream,
                    interrupting_frame: FrameType::Priority,
                    interrupting_stream: frame.stream_id,
                });
                false
            }
            _ => {
                // PRIORITY is allowed when not expecting CONTINUATION
                true
            }
        }
    }

    fn handle_other_frame(&mut self, frame: &Http2Frame) -> bool {
        match &self.header_block_state {
            HeaderBlockState::ExpectingContinuation(expected_stream) => {
                // Any other frame interrupting HEADERS/CONTINUATION sequence
                self.protocol_errors.push(ContinuationError::ContinuationAfterNonHeaders {
                    expected_stream: *expected_stream,
                    interrupting_frame: frame.frame_type,
                    interrupting_stream: frame.stream_id,
                });
                false
            }
            _ => {
                // Other frames are allowed when not expecting CONTINUATION
                true
            }
        }
    }

    fn has_protocol_errors(&self) -> bool {
        !self.protocol_errors.is_empty()
    }

    fn error_count(&self) -> usize {
        self.protocol_errors.len()
    }

    fn is_expecting_continuation(&self) -> bool {
        matches!(self.header_block_state, HeaderBlockState::ExpectingContinuation(_))
    }
}

fuzz_target!(|input: ContinuationOrderingInput| {
    // Skip invalid stream IDs (must be non-zero, client streams are odd)
    if input.stream_id == 0 || input.stream_id % 2 == 0 {
        return;
    }

    // Limit payload size to prevent memory issues
    let payload_size = (input.payload_size as usize).min(256);
    let headers_payload = vec![0x40; payload_size];  // Mock header block
    let continuation_payload = vec![0x41; payload_size.min(128)];

    let mut conn = MockContinuationConnection::new();

    match input.sequence_variant % 8 {
        0 => {
            // Test case 1: Valid sequence - HEADERS(END_HEADERS=1)
            let headers_flags = input.headers_flags | 0x4;  // Set END_HEADERS
            let headers = Http2Frame::new_headers(input.stream_id, headers_flags, headers_payload);

            let accepted = conn.process_frame(&headers);
            assert!(accepted, "Complete HEADERS frame should be accepted");
            assert!(!conn.has_protocol_errors(), "Valid sequence should not cause errors");
            assert!(!conn.is_expecting_continuation(), "Should not be expecting CONTINUATION after END_HEADERS");
        }
        1 => {
            // Test case 2: Valid sequence - HEADERS(END_HEADERS=0) → CONTINUATION(END_HEADERS=1)
            let headers_flags = input.headers_flags & !0x4;  // Clear END_HEADERS
            let continuation_flags = input.continuation_flags | 0x4;  // Set END_HEADERS

            let headers = Http2Frame::new_headers(input.stream_id, headers_flags, headers_payload);
            let continuation = Http2Frame::new_continuation(input.stream_id, continuation_flags, continuation_payload);

            assert!(conn.process_frame(&headers), "HEADERS should be accepted");
            assert!(conn.is_expecting_continuation(), "Should be expecting CONTINUATION");

            assert!(conn.process_frame(&continuation), "CONTINUATION should be accepted");
            assert!(!conn.has_protocol_errors(), "Valid HEADERS→CONTINUATION should not error");
            assert!(!conn.is_expecting_continuation(), "Should complete after END_HEADERS CONTINUATION");
        }
        2 => {
            // Test case 3: INVALID - HEADERS → PRIORITY → CONTINUATION (PROTOCOL_ERROR)
            let headers_flags = input.headers_flags & !0x4;  // Clear END_HEADERS
            let continuation_flags = input.continuation_flags | 0x4;  // Set END_HEADERS

            let headers = Http2Frame::new_headers(input.stream_id, headers_flags, headers_payload);
            let priority = Http2Frame::new_priority(
                input.stream_id,
                false,
                input.priority_dependency & 0x7FFFFFFF,
                input.priority_weight
            );
            let continuation = Http2Frame::new_continuation(input.stream_id, continuation_flags, continuation_payload);

            assert!(conn.process_frame(&headers), "HEADERS should be accepted");
            assert!(conn.is_expecting_continuation(), "Should be expecting CONTINUATION after HEADERS");

            // CRITICAL: PRIORITY frame between HEADERS and CONTINUATION is PROTOCOL_ERROR
            assert!(!conn.process_frame(&priority), "PRIORITY after HEADERS should be rejected");
            assert!(conn.has_protocol_errors(), "Should detect PROTOCOL_ERROR");
            assert_eq!(conn.error_count(), 1, "Should have exactly one error");

            // CONTINUATION after PRIORITY should still be invalid (connection is in error state)
            assert!(!conn.process_frame(&continuation), "CONTINUATION after error should be rejected");
        }
        3 => {
            // Test case 4: INVALID - HEADERS → DATA → CONTINUATION (PROTOCOL_ERROR)
            let headers_flags = input.headers_flags & !0x4;  // Clear END_HEADERS
            let continuation_flags = input.continuation_flags | 0x4;  // Set END_HEADERS

            let headers = Http2Frame::new_headers(input.stream_id, headers_flags, headers_payload);
            let data = Http2Frame::new_data(input.stream_id, 0, vec![0x42; 64]);
            let continuation = Http2Frame::new_continuation(input.stream_id, continuation_flags, continuation_payload);

            assert!(conn.process_frame(&headers), "HEADERS should be accepted");

            // DATA frame interrupting HEADERS/CONTINUATION sequence
            assert!(!conn.process_frame(&data), "DATA after HEADERS should be rejected");
            assert!(conn.has_protocol_errors(), "Should detect PROTOCOL_ERROR for DATA interruption");
        }
        4 => {
            // Test case 5: INVALID - CONTINUATION on wrong stream
            let headers_flags = input.headers_flags & !0x4;  // Clear END_HEADERS
            let wrong_stream_id = if input.stream_id == 1 { 3 } else { 1 };

            let headers = Http2Frame::new_headers(input.stream_id, headers_flags, headers_payload);
            let wrong_continuation = Http2Frame::new_continuation(
                wrong_stream_id,
                input.continuation_flags | 0x4,
                continuation_payload
            );

            assert!(conn.process_frame(&headers), "HEADERS should be accepted");
            assert!(!conn.process_frame(&wrong_continuation), "CONTINUATION on wrong stream should be rejected");
            assert!(conn.has_protocol_errors(), "Should detect stream mismatch");
        }
        5 => {
            // Test case 6: INVALID - CONTINUATION without HEADERS
            let continuation = Http2Frame::new_continuation(
                input.stream_id,
                input.continuation_flags | 0x4,
                continuation_payload
            );

            assert!(!conn.process_frame(&continuation), "Unexpected CONTINUATION should be rejected");
            assert!(conn.has_protocol_errors(), "Should detect unexpected CONTINUATION");
        }
        6 => {
            // Test case 7: Valid sequence - Multiple CONTINUATION frames
            let headers_flags = input.headers_flags & !0x4;  // Clear END_HEADERS
            let mid_continuation_flags = input.continuation_flags & !0x4;  // Clear END_HEADERS
            let final_continuation_flags = input.continuation_flags | 0x4;  // Set END_HEADERS

            let headers = Http2Frame::new_headers(input.stream_id, headers_flags, headers_payload);
            let continuation1 = Http2Frame::new_continuation(input.stream_id, mid_continuation_flags, vec![0x43; 32]);
            let continuation2 = Http2Frame::new_continuation(input.stream_id, final_continuation_flags, continuation_payload);

            assert!(conn.process_frame(&headers), "HEADERS should be accepted");
            assert!(conn.process_frame(&continuation1), "First CONTINUATION should be accepted");
            assert!(conn.is_expecting_continuation(), "Should still expect more CONTINUATION");
            assert!(conn.process_frame(&continuation2), "Final CONTINUATION should be accepted");
            assert!(!conn.is_expecting_continuation(), "Should complete after final CONTINUATION");
            assert!(!conn.has_protocol_errors(), "Valid multi-CONTINUATION sequence should not error");
        }
        7 => {
            // Test case 8: INVALID - PRIORITY on different stream while expecting CONTINUATION
            let headers_flags = input.headers_flags & !0x4;  // Clear END_HEADERS
            let other_stream_id = input.stream_id + 2;  // Different stream

            let headers = Http2Frame::new_headers(input.stream_id, headers_flags, headers_payload);
            let priority_other_stream = Http2Frame::new_priority(
                other_stream_id,
                true,
                0,
                input.priority_weight
            );

            assert!(conn.process_frame(&headers), "HEADERS should be accepted");

            // PRIORITY on different stream while expecting CONTINUATION is still PROTOCOL_ERROR
            // per RFC 7540 §6.10: no other frames allowed between HEADERS and CONTINUATION
            assert!(!conn.process_frame(&priority_other_stream), "PRIORITY on other stream should be rejected");
            assert!(conn.has_protocol_errors(), "Should detect PROTOCOL_ERROR for any interruption");
        }
        _ => unreachable!(),
    }

    // Verify connection state consistency
    assert_eq!(
        conn.valid_sequences + conn.error_count() <= conn.processed_frames,
        true,
        "Connection state should be consistent"
    );
});

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_complete_headers() {
        let mut conn = MockContinuationConnection::new();
        let headers = Http2Frame::new_headers(1, 0x4, vec![0x40, 0x41]);  // END_HEADERS=1

        assert!(conn.process_frame(&headers));
        assert!(!conn.has_protocol_errors());
        assert_eq!(conn.valid_sequences, 1);
    }

    #[test]
    fn test_valid_headers_continuation_sequence() {
        let mut conn = MockContinuationConnection::new();
        let headers = Http2Frame::new_headers(1, 0x0, vec![0x40]);  // END_HEADERS=0
        let continuation = Http2Frame::new_continuation(1, 0x4, vec![0x41]);  // END_HEADERS=1

        assert!(conn.process_frame(&headers));
        assert!(conn.process_frame(&continuation));
        assert!(!conn.has_protocol_errors());
        assert_eq!(conn.valid_sequences, 1);
    }

    #[test]
    fn test_priority_interruption_error() {
        let mut conn = MockContinuationConnection::new();
        let headers = Http2Frame::new_headers(1, 0x0, vec![0x40]);  // END_HEADERS=0
        let priority = Http2Frame::new_priority(1, false, 0, 16);
        let continuation = Http2Frame::new_continuation(1, 0x4, vec![0x41]);  // END_HEADERS=1

        assert!(conn.process_frame(&headers));
        assert!(!conn.process_frame(&priority));  // Should fail
        assert!(conn.has_protocol_errors());
        assert_eq!(conn.error_count(), 1);
    }

    #[test]
    fn test_continuation_wrong_stream() {
        let mut conn = MockContinuationConnection::new();
        let headers = Http2Frame::new_headers(1, 0x0, vec![0x40]);  // END_HEADERS=0
        let continuation = Http2Frame::new_continuation(3, 0x4, vec![0x41]);  // Wrong stream

        assert!(conn.process_frame(&headers));
        assert!(!conn.process_frame(&continuation));
        assert!(conn.has_protocol_errors());
    }

    #[test]
    fn test_unexpected_continuation() {
        let mut conn = MockContinuationConnection::new();
        let continuation = Http2Frame::new_continuation(1, 0x4, vec![0x41]);

        assert!(!conn.process_frame(&continuation));
        assert!(conn.has_protocol_errors());
    }

    #[test]
    fn test_multiple_continuation_frames() {
        let mut conn = MockContinuationConnection::new();
        let headers = Http2Frame::new_headers(1, 0x0, vec![0x40]);  // END_HEADERS=0
        let cont1 = Http2Frame::new_continuation(1, 0x0, vec![0x41]);  // END_HEADERS=0
        let cont2 = Http2Frame::new_continuation(1, 0x4, vec![0x42]);  // END_HEADERS=1

        assert!(conn.process_frame(&headers));
        assert!(conn.process_frame(&cont1));
        assert!(conn.process_frame(&cont2));
        assert!(!conn.has_protocol_errors());
        assert_eq!(conn.valid_sequences, 1);
    }
}