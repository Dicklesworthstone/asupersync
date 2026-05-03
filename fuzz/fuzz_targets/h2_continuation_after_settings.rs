#![no_main]

use libfuzzer_sys::fuzz_target;
use arbitrary::{Arbitrary, Unstructured};

/// HTTP/2 HEADERS/CONTINUATION frame ordering violation testing.
/// Per RFC 7540 §6.10, when HEADERS has END_HEADERS=0, only CONTINUATION
/// frames (for same stream) are allowed until END_HEADERS=1. SETTINGS and
/// other frames must not interleave. Must reject with PROTOCOL_ERROR.
///
/// Tests:
/// - HEADERS with END_HEADERS=0 followed by forbidden frame types
/// - SETTINGS frame interleaving (forbidden)
/// - Valid CONTINUATION sequences (allowed)
/// - PRIORITY frame interleaving (historically allowed)
/// - Stream ID consistency between HEADERS and CONTINUATION
/// - Multiple forbidden frame types in sequence

#[derive(Arbitrary, Debug)]
struct FuzzInput {
    /// Initial HEADERS frame (END_HEADERS=0)
    headers_frame: HeadersFrame,
    /// Sequence of frames that follow the HEADERS
    following_frames: Vec<FrameType>,
    /// Final CONTINUATION (if any)
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
    /// Mock header block fragment continuation
    header_block_fragment: Vec<u8>,
}

#[derive(Arbitrary, Debug, Clone)]
enum FrameType {
    Settings(SettingsFrame),
    Priority(PriorityFrame),
    Data(DataFrame),
    WindowUpdate(WindowUpdateFrame),
    Ping(PingFrame),
    GoAway(GoAwayFrame),
    RstStream(RstStreamFrame),
    Continuation(ContinuationFrame),
    PushPromise(PushPromiseFrame),
}

#[derive(Arbitrary, Debug, Clone)]
struct SettingsFrame {
    flags: u8,
    settings: Vec<(u16, u32)>, // (setting_id, value) pairs
}

#[derive(Arbitrary, Debug, Clone)]
struct PriorityFrame {
    stream_id: u32,
    exclusive: bool,
    dependency: u32,
    weight: u8,
}

#[derive(Arbitrary, Debug, Clone)]
struct DataFrame {
    stream_id: u32,
    flags: u8,
    data: Vec<u8>,
}

#[derive(Arbitrary, Debug, Clone)]
struct WindowUpdateFrame {
    stream_id: u32,
    increment: u32,
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
struct RstStreamFrame {
    stream_id: u32,
    error_code: u32,
}

#[derive(Arbitrary, Debug, Clone)]
struct PushPromiseFrame {
    stream_id: u32,
    flags: u8,
    promised_stream_id: u32,
    header_block_fragment: Vec<u8>,
}

/// HTTP/2 frame parser state for HEADERS/CONTINUATION tracking
#[derive(Debug, PartialEq)]
enum ParserState {
    /// No ongoing header block
    Idle,
    /// Expecting CONTINUATION for specific stream
    AwaitingContinuation(u32), // stream_id
}

/// Mock HTTP/2 frame parser with HEADERS/CONTINUATION state tracking
struct MockH2FrameParser {
    state: ParserState,
    errors: Vec<String>,
}

impl MockH2FrameParser {
    fn new() -> Self {
        Self {
            state: ParserState::Idle,
            errors: Vec::new(),
        }
    }

    /// Process HEADERS frame
    fn process_headers(&mut self, frame: &HeadersFrame) -> Result<(), String> {
        // Validate stream ID
        if frame.stream_id == 0 {
            return Err("HEADERS frame stream ID must not be 0".into());
        }

        // Check if we're already expecting CONTINUATION
        if let ParserState::AwaitingContinuation(stream_id) = self.state {
            return Err(format!(
                "PROTOCOL_ERROR: received HEADERS while expecting CONTINUATION for stream {}",
                stream_id
            ));
        }

        // Force END_HEADERS=0 for this test
        let end_headers = (frame.flags & 0x04) != 0;

        if !end_headers {
            // Incomplete header block - expect CONTINUATION
            self.state = ParserState::AwaitingContinuation(frame.stream_id);
        }

        Ok(())
    }

    /// Process frame in CONTINUATION-awaiting state
    fn process_frame_during_continuation(&mut self, frame: &FrameType) -> Result<(), String> {
        if let ParserState::AwaitingContinuation(expected_stream_id) = self.state {
            match frame {
                FrameType::Continuation(cont_frame) => {
                    // CONTINUATION frame - check stream ID
                    if cont_frame.stream_id != expected_stream_id {
                        return Err(format!(
                            "PROTOCOL_ERROR: CONTINUATION stream ID {} does not match HEADERS stream ID {}",
                            cont_frame.stream_id, expected_stream_id
                        ));
                    }

                    // Check if this completes the header block
                    let end_headers = (cont_frame.flags & 0x04) != 0;
                    if end_headers {
                        self.state = ParserState::Idle;
                    }

                    Ok(())
                }
                FrameType::Priority(priority_frame) => {
                    // PRIORITY frames historically allowed during CONTINUATION sequence
                    // (though this may be deprecated in newer specs)
                    // For this test, we'll allow PRIORITY but flag it as potentially deprecated
                    self.errors.push(format!(
                        "PRIORITY frame during CONTINUATION sequence (deprecated behavior): stream {}",
                        priority_frame.stream_id
                    ));
                    Ok(())
                }
                FrameType::Settings(_) => {
                    // SETTINGS frame forbidden during CONTINUATION sequence
                    Err("PROTOCOL_ERROR: SETTINGS frame not allowed between HEADERS and CONTINUATION".into())
                }
                FrameType::Data(data_frame) => {
                    Err(format!(
                        "PROTOCOL_ERROR: DATA frame not allowed between HEADERS and CONTINUATION (stream {})",
                        data_frame.stream_id
                    ))
                }
                FrameType::WindowUpdate(wu_frame) => {
                    Err(format!(
                        "PROTOCOL_ERROR: WINDOW_UPDATE frame not allowed between HEADERS and CONTINUATION (stream {})",
                        wu_frame.stream_id
                    ))
                }
                FrameType::Ping(_) => {
                    Err("PROTOCOL_ERROR: PING frame not allowed between HEADERS and CONTINUATION".into())
                }
                FrameType::GoAway(_) => {
                    Err("PROTOCOL_ERROR: GOAWAY frame not allowed between HEADERS and CONTINUATION".into())
                }
                FrameType::RstStream(rst_frame) => {
                    Err(format!(
                        "PROTOCOL_ERROR: RST_STREAM frame not allowed between HEADERS and CONTINUATION (stream {})",
                        rst_frame.stream_id
                    ))
                }
                FrameType::PushPromise(pp_frame) => {
                    Err(format!(
                        "PROTOCOL_ERROR: PUSH_PROMISE frame not allowed between HEADERS and CONTINUATION (stream {})",
                        pp_frame.stream_id
                    ))
                }
            }
        } else {
            // Not in CONTINUATION state - frame is allowed
            self.process_regular_frame(frame)
        }
    }

    /// Process frame when not waiting for CONTINUATION
    fn process_regular_frame(&mut self, frame: &FrameType) -> Result<(), String> {
        match frame {
            FrameType::Continuation(cont_frame) => {
                Err(format!(
                    "PROTOCOL_ERROR: CONTINUATION frame without preceding HEADERS (stream {})",
                    cont_frame.stream_id
                ))
            }
            _ => Ok(()), // Other frames are generally allowed when not in CONTINUATION state
        }
    }

    /// Process complete frame sequence
    fn process_sequence(&mut self, input: &FuzzInput) -> Result<(), String> {
        // Process initial HEADERS frame (with END_HEADERS=0 forced)
        let mut headers = input.headers_frame.clone();
        headers.flags &= !0x04; // Clear END_HEADERS flag

        self.process_headers(&headers)?;

        // Process following frames
        for frame in &input.following_frames {
            self.process_frame_during_continuation(frame)?;
        }

        // Process final CONTINUATION if present
        if let Some(final_cont) = &input.final_continuation {
            self.process_frame_during_continuation(&FrameType::Continuation(final_cont.clone()))?;
        }

        // Check if we're still waiting for CONTINUATION
        if let ParserState::AwaitingContinuation(stream_id) = self.state {
            return Err(format!(
                "PROTOCOL_ERROR: incomplete header block for stream {} (no final CONTINUATION with END_HEADERS)",
                stream_id
            ));
        }

        Ok(())
    }

    /// Get current parser state for verification
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
    if input.following_frames.len() > 20 {
        return;
    }

    if input.headers_frame.header_block_fragment.len() > 1000 {
        return;
    }

    // Ensure stream ID is valid for HEADERS
    if input.headers_frame.stream_id == 0 || input.headers_frame.stream_id > 1_000_000 {
        return;
    }

    let mut parser = MockH2FrameParser::new();
    let result = parser.process_sequence(&input);

    // Test 1: SETTINGS frame should cause PROTOCOL_ERROR
    let has_settings_frame = input.following_frames.iter().any(|frame| {
        matches!(frame, FrameType::Settings(_))
    });

    if has_settings_frame {
        assert!(result.is_err(),
            "SETTINGS frame during CONTINUATION sequence should be rejected");

        if let Err(error_msg) = &result {
            assert!(error_msg.contains("PROTOCOL_ERROR") || error_msg.contains("not allowed"),
                "SETTINGS interleaving should generate PROTOCOL_ERROR: {}", error_msg);
        }
    }

    // Test 2: Other forbidden frames should also cause PROTOCOL_ERROR
    let forbidden_frame_types = [
        "Data", "WindowUpdate", "Ping", "GoAway", "RstStream", "PushPromise"
    ];

    for frame in &input.following_frames {
        let frame_name = match frame {
            FrameType::Data(_) => "Data",
            FrameType::WindowUpdate(_) => "WindowUpdate",
            FrameType::Ping(_) => "Ping",
            FrameType::GoAway(_) => "GoAway",
            FrameType::RstStream(_) => "RstStream",
            FrameType::PushPromise(_) => "PushPromise",
            _ => continue,
        };

        if forbidden_frame_types.contains(&frame_name) {
            assert!(result.is_err(),
                "{} frame during CONTINUATION sequence should be rejected", frame_name);

            if let Err(error_msg) = &result {
                assert!(error_msg.contains("PROTOCOL_ERROR") || error_msg.contains("not allowed"),
                    "{} interleaving should generate PROTOCOL_ERROR: {}", frame_name, error_msg);
            }
        }
    }

    // Test 3: Valid CONTINUATION sequences should work
    let only_continuation_and_priority = input.following_frames.iter().all(|frame| {
        matches!(frame, FrameType::Continuation(_) | FrameType::Priority(_))
    });

    let has_proper_end = input.final_continuation.as_ref()
        .map(|cont| (cont.flags & 0x04) != 0) // END_HEADERS set
        .unwrap_or(false);

    if only_continuation_and_priority && has_proper_end {
        // Check if all CONTINUATION frames have matching stream ID
        let all_matching_stream_id = input.following_frames.iter()
            .filter_map(|frame| {
                if let FrameType::Continuation(cont) = frame {
                    Some(cont.stream_id == input.headers_frame.stream_id)
                } else {
                    None
                }
            })
            .all(|matches| matches);

        let final_matches = input.final_continuation.as_ref()
            .map(|cont| cont.stream_id == input.headers_frame.stream_id)
            .unwrap_or(true);

        if all_matching_stream_id && final_matches {
            if result.is_err() {
                // Valid sequence failed - check if it's due to stream ID mismatch or other valid reason
                if let Err(error_msg) = &result {
                    assert!(
                        error_msg.contains("stream ID") ||
                        error_msg.contains("incomplete") ||
                        error_msg.contains("PRIORITY frame during CONTINUATION sequence"),
                        "Valid CONTINUATION sequence failed unexpectedly: {}", error_msg
                    );
                }
            }
        }
    }

    // Test 4: Stream ID mismatches should be caught
    for frame in &input.following_frames {
        if let FrameType::Continuation(cont) = frame {
            if cont.stream_id != input.headers_frame.stream_id {
                assert!(result.is_err(),
                    "CONTINUATION with mismatched stream ID should be rejected");

                if let Err(error_msg) = &result {
                    assert!(error_msg.contains("stream ID") && error_msg.contains("PROTOCOL_ERROR"),
                        "Stream ID mismatch should generate specific error: {}", error_msg);
                }
            }
        }
    }
});

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_settings_interleaving_forbidden() {
        let input = FuzzInput {
            headers_frame: HeadersFrame {
                stream_id: 1,
                flags: 0, // END_HEADERS=0
                header_block_fragment: b"mock-headers".to_vec(),
            },
            following_frames: vec![
                FrameType::Settings(SettingsFrame {
                    flags: 0,
                    settings: vec![(1, 4096)], // HEADER_TABLE_SIZE
                }),
            ],
            final_continuation: Some(ContinuationFrame {
                stream_id: 1,
                flags: 0x04, // END_HEADERS=1
                header_block_fragment: b"mock-cont".to_vec(),
            }),
        };

        let mut parser = MockH2FrameParser::new();
        let result = parser.process_sequence(&input);

        assert!(result.is_err());
        assert!(result.unwrap_err().contains("SETTINGS frame not allowed"));
    }

    #[test]
    fn test_valid_continuation_sequence() {
        let input = FuzzInput {
            headers_frame: HeadersFrame {
                stream_id: 1,
                flags: 0, // END_HEADERS=0
                header_block_fragment: b"mock-headers".to_vec(),
            },
            following_frames: vec![
                FrameType::Continuation(ContinuationFrame {
                    stream_id: 1,
                    flags: 0, // END_HEADERS=0
                    header_block_fragment: b"mock-cont1".to_vec(),
                }),
            ],
            final_continuation: Some(ContinuationFrame {
                stream_id: 1,
                flags: 0x04, // END_HEADERS=1
                header_block_fragment: b"mock-cont2".to_vec(),
            }),
        };

        let mut parser = MockH2FrameParser::new();
        let result = parser.process_sequence(&input);

        assert!(result.is_ok());
        assert_eq!(parser.get_state(), &ParserState::Idle);
    }

    #[test]
    fn test_priority_interleaving_deprecated() {
        let input = FuzzInput {
            headers_frame: HeadersFrame {
                stream_id: 1,
                flags: 0, // END_HEADERS=0
                header_block_fragment: b"mock-headers".to_vec(),
            },
            following_frames: vec![
                FrameType::Priority(PriorityFrame {
                    stream_id: 1,
                    exclusive: false,
                    dependency: 0,
                    weight: 15,
                }),
            ],
            final_continuation: Some(ContinuationFrame {
                stream_id: 1,
                flags: 0x04, // END_HEADERS=1
                header_block_fragment: b"mock-cont".to_vec(),
            }),
        };

        let mut parser = MockH2FrameParser::new();
        let result = parser.process_sequence(&input);

        // Should work but generate warning
        assert!(result.is_ok());
        assert!(!parser.errors.is_empty());
        assert!(parser.errors[0].contains("PRIORITY frame during CONTINUATION"));
    }

    #[test]
    fn test_stream_id_mismatch() {
        let input = FuzzInput {
            headers_frame: HeadersFrame {
                stream_id: 1,
                flags: 0, // END_HEADERS=0
                header_block_fragment: b"mock-headers".to_vec(),
            },
            following_frames: vec![
                FrameType::Continuation(ContinuationFrame {
                    stream_id: 3, // Wrong stream ID
                    flags: 0x04, // END_HEADERS=1
                    header_block_fragment: b"mock-cont".to_vec(),
                }),
            ],
            final_continuation: None,
        };

        let mut parser = MockH2FrameParser::new();
        let result = parser.process_sequence(&input);

        assert!(result.is_err());
        assert!(result.unwrap_err().contains("CONTINUATION stream ID"));
    }

    #[test]
    fn test_data_frame_forbidden() {
        let input = FuzzInput {
            headers_frame: HeadersFrame {
                stream_id: 1,
                flags: 0, // END_HEADERS=0
                header_block_fragment: b"mock-headers".to_vec(),
            },
            following_frames: vec![
                FrameType::Data(DataFrame {
                    stream_id: 1,
                    flags: 0,
                    data: b"some data".to_vec(),
                }),
            ],
            final_continuation: None,
        };

        let mut parser = MockH2FrameParser::new();
        let result = parser.process_sequence(&input);

        assert!(result.is_err());
        assert!(result.unwrap_err().contains("DATA frame not allowed"));
    }

    #[test]
    fn test_incomplete_header_block() {
        let input = FuzzInput {
            headers_frame: HeadersFrame {
                stream_id: 1,
                flags: 0, // END_HEADERS=0
                header_block_fragment: b"mock-headers".to_vec(),
            },
            following_frames: vec![],
            final_continuation: None, // No CONTINUATION with END_HEADERS=1
        };

        let mut parser = MockH2FrameParser::new();
        let result = parser.process_sequence(&input);

        assert!(result.is_err());
        assert!(result.unwrap_err().contains("incomplete header block"));
    }
}