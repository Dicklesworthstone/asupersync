#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use libfuzzer_sys::fuzz_target;
use std::hint::black_box;

/// HTTP/2 HEADERS/CONTINUATION sequence interruption testing.
/// Per RFC 7540 §6.10, CONTINUATION frames must IMMEDIATELY follow
/// HEADERS/PUSH_PROMISE with END_HEADERS=0. ANY other frame between
/// is PROTOCOL_ERROR, even if on different stream.
///
/// Tests:
/// - HEADERS (END_HEADERS=0) interrupted by DATA on different stream
/// - HEADERS interrupted by various frame types on any stream
/// - Valid HEADERS/CONTINUATION sequences (uninterrupted)
/// - Multiple interrupting frames
/// - Same-stream vs different-stream interruption
/// - Global parser state tracking across streams

#[derive(Arbitrary, Debug)]
struct FuzzInput {
    /// Initial HEADERS frame (END_HEADERS=0 forced)
    headers_frame: HeadersFrame,
    /// Sequence of frames that may interrupt CONTINUATION
    interrupting_frames: Vec<FrameType>,
    /// Final CONTINUATION frame (if any)
    final_continuation: Option<ContinuationFrame>,
}

#[derive(Arbitrary, Debug, Clone)]
struct HeadersFrame {
    /// Stream ID (must be > 0)
    stream_id: u32,
    /// Frame flags (END_HEADERS will be forced to 0)
    flags: u8,
    /// Mock header block fragment
    header_block_fragment: Vec<u8>,
}

#[derive(Arbitrary, Debug, Clone)]
struct ContinuationFrame {
    /// Stream ID (should match HEADERS for valid sequence)
    stream_id: u32,
    /// Frame flags (END_HEADERS may be 0 or 1)
    flags: u8,
    /// Mock header block fragment
    header_block_fragment: Vec<u8>,
}

#[derive(Arbitrary, Debug, Clone)]
enum FrameType {
    Data(DataFrame),
    Headers(HeadersFrame),
    Priority(PriorityFrame),
    RstStream(RstStreamFrame),
    Settings(SettingsFrame),
    PushPromise(PushPromiseFrame),
    Ping(PingFrame),
    GoAway(GoAwayFrame),
    WindowUpdate(WindowUpdateFrame),
    Continuation(ContinuationFrame),
}

#[derive(Arbitrary, Debug, Clone)]
struct DataFrame {
    stream_id: u32,
    flags: u8,
    data: Vec<u8>,
}

#[derive(Arbitrary, Debug, Clone)]
struct PriorityFrame {
    stream_id: u32,
    exclusive: bool,
    dependency: u32,
    weight: u8,
}

#[derive(Arbitrary, Debug, Clone)]
struct RstStreamFrame {
    stream_id: u32,
    error_code: u32,
}

#[derive(Arbitrary, Debug, Clone)]
struct SettingsFrame {
    flags: u8,
    settings: Vec<(u16, u32)>,
}

#[derive(Arbitrary, Debug, Clone)]
struct PushPromiseFrame {
    stream_id: u32,
    flags: u8,
    promised_stream_id: u32,
    header_block_fragment: Vec<u8>,
}

#[derive(Arbitrary, Debug, Clone)]
struct PingFrame {
    flags: u8,
    data: [u8; 8],
}

#[derive(Arbitrary, Debug, Clone)]
struct GoAwayFrame {
    last_stream_id: u32,
    error_code: u32,
    debug_data: Vec<u8>,
}

#[derive(Arbitrary, Debug, Clone)]
struct WindowUpdateFrame {
    stream_id: u32,
    increment: u32,
}

/// HTTP/2 frame parser state for strict HEADERS/CONTINUATION tracking
#[derive(Debug, PartialEq)]
enum ParserState {
    /// No ongoing header block
    Idle,
    /// Expecting CONTINUATION for specific stream - NO other frames allowed
    ExpectingContinuation(u32), // stream_id
}

/// Mock HTTP/2 frame parser with strict CONTINUATION sequence enforcement
struct MockH2StrictParser {
    state: ParserState,
}

impl MockH2StrictParser {
    fn new() -> Self {
        Self {
            state: ParserState::Idle,
        }
    }

    /// Process frame with strict CONTINUATION enforcement
    fn process_frame(&mut self, frame: &FrameType) -> Result<(), String> {
        Self::observe_frame_metadata(frame);

        // If we're expecting CONTINUATION, NO other frames are allowed
        if let ParserState::ExpectingContinuation(expected_stream_id) = self.state {
            match frame {
                FrameType::Continuation(cont_frame) => {
                    return self.process_continuation(cont_frame, expected_stream_id);
                }
                _ => {
                    // ANY non-CONTINUATION frame is PROTOCOL_ERROR
                    let frame_name = self.get_frame_name(frame);
                    let frame_stream_id = self.get_frame_stream_id(frame);

                    return Err(format!(
                        "PROTOCOL_ERROR: {} frame on stream {} interrupts HEADERS/CONTINUATION sequence (expecting CONTINUATION for stream {})",
                        frame_name, frame_stream_id, expected_stream_id
                    ));
                }
            }
        }

        // Not in CONTINUATION state - process normally
        self.process_regular_frame(frame)
    }

    /// Process CONTINUATION frame when expected
    fn process_continuation(
        &mut self,
        frame: &ContinuationFrame,
        expected_stream_id: u32,
    ) -> Result<(), String> {
        // Validate stream ID matches
        if frame.stream_id != expected_stream_id {
            return Err(format!(
                "PROTOCOL_ERROR: CONTINUATION stream ID {} does not match expected {}",
                frame.stream_id, expected_stream_id
            ));
        }

        // Check if this completes the header block
        let end_headers = (frame.flags & 0x04) != 0;
        if end_headers {
            self.state = ParserState::Idle;
        }
        // If not END_HEADERS, stay in ExpectingContinuation state

        Ok(())
    }

    /// Process frame when not in CONTINUATION state
    fn process_regular_frame(&mut self, frame: &FrameType) -> Result<(), String> {
        match frame {
            FrameType::Headers(headers_frame) => self.process_headers(headers_frame),
            FrameType::PushPromise(pp_frame) => self.process_push_promise(pp_frame),
            FrameType::Continuation(cont_frame) => Err(format!(
                "PROTOCOL_ERROR: CONTINUATION frame on stream {} without preceding HEADERS",
                cont_frame.stream_id
            )),
            _ => {
                // Other frames are generally allowed when not in CONTINUATION state
                self.validate_frame(frame)
            }
        }
    }

    /// Process HEADERS frame
    fn process_headers(&mut self, frame: &HeadersFrame) -> Result<(), String> {
        if frame.stream_id == 0 {
            return Err("PROTOCOL_ERROR: HEADERS frame stream ID must not be 0".into());
        }

        // Check END_HEADERS flag
        let end_headers = (frame.flags & 0x04) != 0;

        if !end_headers {
            // Incomplete header block - expect CONTINUATION
            self.state = ParserState::ExpectingContinuation(frame.stream_id);
        }

        Ok(())
    }

    /// Process PUSH_PROMISE frame
    fn process_push_promise(&mut self, frame: &PushPromiseFrame) -> Result<(), String> {
        if frame.stream_id == 0 {
            return Err("PROTOCOL_ERROR: PUSH_PROMISE frame stream ID must not be 0".into());
        }

        // Check END_HEADERS flag
        let end_headers = (frame.flags & 0x04) != 0;

        if !end_headers {
            // Incomplete header block - expect CONTINUATION
            self.state = ParserState::ExpectingContinuation(frame.stream_id);
        }

        Ok(())
    }

    /// Basic frame validation
    fn validate_frame(&mut self, frame: &FrameType) -> Result<(), String> {
        match frame {
            FrameType::Data(data_frame) => {
                if data_frame.stream_id == 0 {
                    return Err("PROTOCOL_ERROR: DATA frame stream ID must not be 0".into());
                }
            }
            FrameType::Priority(priority_frame) => {
                if priority_frame.stream_id == 0 {
                    return Err("PROTOCOL_ERROR: PRIORITY frame stream ID must not be 0".into());
                }
            }
            FrameType::RstStream(rst_frame) => {
                if rst_frame.stream_id == 0 {
                    return Err("PROTOCOL_ERROR: RST_STREAM frame stream ID must not be 0".into());
                }
            }
            FrameType::Settings(_) => {
                // SETTINGS frames are connection-level (stream ID 0)
            }
            FrameType::Ping(_) => {
                // PING frames are connection-level
            }
            FrameType::GoAway(_) => {
                // GOAWAY frames are connection-level
            }
            FrameType::WindowUpdate(wu_frame) => {
                // WINDOW_UPDATE can be connection-level (0) or stream-level (>0)
                if wu_frame.increment == 0 {
                    return Err("PROTOCOL_ERROR: WINDOW_UPDATE increment must not be 0".into());
                }
            }
            _ => {}
        }

        Ok(())
    }

    /// Get frame type name for error messages
    fn get_frame_name(&self, frame: &FrameType) -> &'static str {
        match frame {
            FrameType::Data(_) => "DATA",
            FrameType::Headers(_) => "HEADERS",
            FrameType::Priority(_) => "PRIORITY",
            FrameType::RstStream(_) => "RST_STREAM",
            FrameType::Settings(_) => "SETTINGS",
            FrameType::PushPromise(_) => "PUSH_PROMISE",
            FrameType::Ping(_) => "PING",
            FrameType::GoAway(_) => "GOAWAY",
            FrameType::WindowUpdate(_) => "WINDOW_UPDATE",
            FrameType::Continuation(_) => "CONTINUATION",
        }
    }

    /// Get frame stream ID for error messages
    fn get_frame_stream_id(&self, frame: &FrameType) -> u32 {
        match frame {
            FrameType::Data(f) => f.stream_id,
            FrameType::Headers(f) => f.stream_id,
            FrameType::Priority(f) => f.stream_id,
            FrameType::RstStream(f) => f.stream_id,
            FrameType::Settings(_) => 0,
            FrameType::PushPromise(f) => f.stream_id,
            FrameType::Ping(_) => 0,
            FrameType::GoAway(_) => 0,
            FrameType::WindowUpdate(f) => f.stream_id,
            FrameType::Continuation(f) => f.stream_id,
        }
    }

    fn observe_frame_metadata(frame: &FrameType) {
        match frame {
            FrameType::Data(f) => {
                black_box(f.flags);
                black_box(f.data.len());
            }
            FrameType::Headers(f) => {
                black_box(f.header_block_fragment.len());
            }
            FrameType::Priority(f) => {
                black_box(f.exclusive);
                black_box(f.dependency);
                black_box(f.weight);
            }
            FrameType::RstStream(f) => {
                black_box(f.error_code);
            }
            FrameType::Settings(f) => {
                black_box(f.flags);
                black_box(f.settings.len());
            }
            FrameType::PushPromise(f) => {
                black_box(f.promised_stream_id);
                black_box(f.header_block_fragment.len());
            }
            FrameType::Ping(f) => {
                black_box(f.flags);
                black_box(f.data);
            }
            FrameType::GoAway(f) => {
                black_box(f.last_stream_id);
                black_box(f.error_code);
                black_box(f.debug_data.len());
            }
            FrameType::WindowUpdate(_) => {}
            FrameType::Continuation(f) => {
                black_box(f.header_block_fragment.len());
            }
        }
    }

    /// Process complete frame sequence
    fn process_sequence(&mut self, input: &FuzzInput) -> Result<(), String> {
        // Process initial HEADERS frame (force END_HEADERS=0)
        let mut headers = input.headers_frame.clone();
        headers.flags &= !0x04; // Clear END_HEADERS flag

        self.process_headers(&headers)?;

        // Process interrupting frames
        for frame in &input.interrupting_frames {
            self.process_frame(frame)?;
        }

        // Process final CONTINUATION if present
        if let Some(final_cont) = &input.final_continuation {
            self.process_frame(&FrameType::Continuation(final_cont.clone()))?;
        }

        // Check if we're still waiting for CONTINUATION
        if let ParserState::ExpectingContinuation(stream_id) = self.state {
            return Err(format!(
                "PROTOCOL_ERROR: incomplete header block for stream {} (no final CONTINUATION with END_HEADERS)",
                stream_id
            ));
        }

        Ok(())
    }

    /// Get current parser state
    fn get_state(&self) -> &ParserState {
        &self.state
    }
}

fuzz_target!(|data: &[u8]| {
    let mut u = Unstructured::new(data);
    let input: FuzzInput = match u.arbitrary() {
        Ok(input) => input,
        Err(_) => return, // Skip invalid inputs
    };

    // Limit sizes to prevent timeouts
    if input.interrupting_frames.len() > 10 {
        return;
    }

    if input.headers_frame.header_block_fragment.len() > 1000 {
        return;
    }

    // Ensure valid stream ID for HEADERS
    if input.headers_frame.stream_id == 0 || input.headers_frame.stream_id > 1_000_000 {
        return;
    }

    let mut parser = MockH2StrictParser::new();
    let result = parser.process_sequence(&input);

    // Test 1: ANY non-CONTINUATION frame should cause PROTOCOL_ERROR
    if !input.interrupting_frames.is_empty() {
        let has_non_continuation = input
            .interrupting_frames
            .iter()
            .any(|frame| !matches!(frame, FrameType::Continuation(_)));

        if has_non_continuation {
            assert!(
                result.is_err(),
                "Non-CONTINUATION frame interrupting HEADERS/CONTINUATION should be PROTOCOL_ERROR"
            );

            if let Err(error_msg) = &result {
                assert!(
                    error_msg.contains("PROTOCOL_ERROR"),
                    "Interruption error should mention PROTOCOL_ERROR: {}",
                    error_msg
                );
                assert!(
                    error_msg.contains("interrupts"),
                    "Interruption error should mention interruption: {}",
                    error_msg
                );
            }
            return; // No further tests for interruption case
        }
    }

    // Test 2: DATA frame on different stream should be caught
    let has_data_frame = input
        .interrupting_frames
        .iter()
        .any(|frame| matches!(frame, FrameType::Data(_)));

    if has_data_frame {
        assert!(
            result.is_err(),
            "DATA frame interrupting HEADERS/CONTINUATION should be PROTOCOL_ERROR"
        );

        if let Err(error_msg) = &result {
            assert!(
                error_msg.contains("DATA frame") && error_msg.contains("interrupts"),
                "DATA interruption error should be specific: {}",
                error_msg
            );
        }
        return;
    }

    // Test 3: Valid CONTINUATION-only sequences should work
    let only_continuations = input
        .interrupting_frames
        .iter()
        .all(|frame| matches!(frame, FrameType::Continuation(_)));

    if only_continuations {
        // Check if all CONTINUATIONs have matching stream ID
        let all_matching_stream_id = input
            .interrupting_frames
            .iter()
            .filter_map(|frame| {
                if let FrameType::Continuation(cont) = frame {
                    Some(cont.stream_id == input.headers_frame.stream_id)
                } else {
                    None
                }
            })
            .all(|matches| matches);

        // Check if final CONTINUATION has matching stream ID and END_HEADERS
        let final_valid = input
            .final_continuation
            .as_ref()
            .map(|cont| {
                cont.stream_id == input.headers_frame.stream_id && (cont.flags & 0x04) != 0 // END_HEADERS set
            })
            .unwrap_or(false);

        if all_matching_stream_id && final_valid {
            assert!(
                result.is_ok(),
                "Valid CONTINUATION-only sequence should succeed"
            );
            assert_eq!(
                parser.get_state(),
                &ParserState::Idle,
                "Parser should return to idle state after complete sequence"
            );
        } else if !final_valid {
            assert!(
                result.is_err(),
                "Incomplete CONTINUATION sequence should fail"
            );
            if let Err(error_msg) = &result {
                assert!(
                    error_msg.contains("incomplete header block")
                        || error_msg.contains("stream ID"),
                    "Incomplete sequence error should be clear: {}",
                    error_msg
                );
            }
        }
    }

    // Test 4: Stream ID mismatches in CONTINUATION should be caught
    for frame in &input.interrupting_frames {
        if let FrameType::Continuation(cont) = frame
            && cont.stream_id != input.headers_frame.stream_id
        {
            assert!(
                result.is_err(),
                "CONTINUATION with wrong stream ID should be rejected"
            );

            if let Err(error_msg) = &result {
                assert!(
                    error_msg.contains("stream ID") && error_msg.contains("does not match"),
                    "Stream ID mismatch error should be clear: {}",
                    error_msg
                );
            }
            return;
        }
    }
});

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_data_frame_interruption() {
        let input = FuzzInput {
            headers_frame: HeadersFrame {
                stream_id: 1,
                flags: 0, // END_HEADERS=0 (forced)
                header_block_fragment: b"mock-headers".to_vec(),
            },
            interrupting_frames: vec![FrameType::Data(DataFrame {
                stream_id: 3, // Different stream
                flags: 0,
                data: b"some data".to_vec(),
            })],
            final_continuation: Some(ContinuationFrame {
                stream_id: 1,
                flags: 0x04, // END_HEADERS=1
                header_block_fragment: b"mock-cont".to_vec(),
            }),
        };

        let mut parser = MockH2StrictParser::new();
        let result = parser.process_sequence(&input);

        assert!(result.is_err());
        assert!(result.unwrap_err().contains("DATA frame"));
        assert!(result.unwrap_err().contains("interrupts"));
    }

    #[test]
    fn test_settings_frame_interruption() {
        let input = FuzzInput {
            headers_frame: HeadersFrame {
                stream_id: 1,
                flags: 0,
                header_block_fragment: b"mock-headers".to_vec(),
            },
            interrupting_frames: vec![FrameType::Settings(SettingsFrame {
                flags: 0,
                settings: vec![(1, 4096)],
            })],
            final_continuation: None,
        };

        let mut parser = MockH2StrictParser::new();
        let result = parser.process_sequence(&input);

        assert!(result.is_err());
        assert!(result.unwrap_err().contains("SETTINGS frame"));
        assert!(result.unwrap_err().contains("interrupts"));
    }

    #[test]
    fn test_valid_continuation_sequence() {
        let input = FuzzInput {
            headers_frame: HeadersFrame {
                stream_id: 1,
                flags: 0,
                header_block_fragment: b"mock-headers".to_vec(),
            },
            interrupting_frames: vec![FrameType::Continuation(ContinuationFrame {
                stream_id: 1,
                flags: 0, // END_HEADERS=0
                header_block_fragment: b"mock-cont1".to_vec(),
            })],
            final_continuation: Some(ContinuationFrame {
                stream_id: 1,
                flags: 0x04, // END_HEADERS=1
                header_block_fragment: b"mock-cont2".to_vec(),
            }),
        };

        let mut parser = MockH2StrictParser::new();
        let result = parser.process_sequence(&input);

        assert!(result.is_ok());
        assert_eq!(parser.get_state(), &ParserState::Idle);
    }

    #[test]
    fn test_priority_frame_same_stream_interruption() {
        let input = FuzzInput {
            headers_frame: HeadersFrame {
                stream_id: 5,
                flags: 0,
                header_block_fragment: b"mock-headers".to_vec(),
            },
            interrupting_frames: vec![FrameType::Priority(PriorityFrame {
                stream_id: 5, // Same stream as HEADERS
                exclusive: false,
                dependency: 0,
                weight: 15,
            })],
            final_continuation: None,
        };

        let mut parser = MockH2StrictParser::new();
        let result = parser.process_sequence(&input);

        assert!(result.is_err());
        assert!(result.unwrap_err().contains("PRIORITY frame"));
        assert!(result.unwrap_err().contains("interrupts"));
    }

    #[test]
    fn test_continuation_wrong_stream_id() {
        let input = FuzzInput {
            headers_frame: HeadersFrame {
                stream_id: 1,
                flags: 0,
                header_block_fragment: b"mock-headers".to_vec(),
            },
            interrupting_frames: vec![FrameType::Continuation(ContinuationFrame {
                stream_id: 3, // Wrong stream ID
                flags: 0x04,
                header_block_fragment: b"mock-cont".to_vec(),
            })],
            final_continuation: None,
        };

        let mut parser = MockH2StrictParser::new();
        let result = parser.process_sequence(&input);

        assert!(result.is_err());
        assert!(result.unwrap_err().contains("CONTINUATION stream ID"));
        assert!(result.unwrap_err().contains("does not match"));
    }

    #[test]
    fn test_multiple_frame_types_interruption() {
        let input = FuzzInput {
            headers_frame: HeadersFrame {
                stream_id: 1,
                flags: 0,
                header_block_fragment: b"mock-headers".to_vec(),
            },
            interrupting_frames: vec![
                FrameType::WindowUpdate(WindowUpdateFrame {
                    stream_id: 0, // Connection-level
                    increment: 1000,
                }),
                FrameType::Ping(PingFrame {
                    flags: 0,
                    data: [1, 2, 3, 4, 5, 6, 7, 8],
                }),
            ],
            final_continuation: None,
        };

        let mut parser = MockH2StrictParser::new();
        let result = parser.process_sequence(&input);

        assert!(result.is_err());
        // Should fail on first non-CONTINUATION frame
        assert!(result.unwrap_err().contains("WINDOW_UPDATE frame"));
    }

    #[test]
    fn test_incomplete_header_block() {
        let input = FuzzInput {
            headers_frame: HeadersFrame {
                stream_id: 1,
                flags: 0, // END_HEADERS=0
                header_block_fragment: b"mock-headers".to_vec(),
            },
            interrupting_frames: vec![], // No interrupting frames
            final_continuation: None,    // No final CONTINUATION
        };

        let mut parser = MockH2StrictParser::new();
        let result = parser.process_sequence(&input);

        assert!(result.is_err());
        assert!(result.unwrap_err().contains("incomplete header block"));
    }

    #[test]
    fn test_rst_stream_interruption() {
        let input = FuzzInput {
            headers_frame: HeadersFrame {
                stream_id: 1,
                flags: 0,
                header_block_fragment: b"mock-headers".to_vec(),
            },
            interrupting_frames: vec![FrameType::RstStream(RstStreamFrame {
                stream_id: 1,  // Same stream
                error_code: 8, // CANCEL
            })],
            final_continuation: None,
        };

        let mut parser = MockH2StrictParser::new();
        let result = parser.process_sequence(&input);

        assert!(result.is_err());
        assert!(result.unwrap_err().contains("RST_STREAM frame"));
        assert!(result.unwrap_err().contains("interrupts"));
    }
}
