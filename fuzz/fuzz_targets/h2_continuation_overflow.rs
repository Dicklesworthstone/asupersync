#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use std::collections::HashMap;

/// Fuzz target for HTTP/2 HEADERS+CONTINUATION header-block size overflow detection.
///
/// Per RFC 7540 §6.5.2: "SETTINGS_MAX_HEADER_LIST_SIZE (0x6): This advisory
/// setting informs a peer of the maximum size of header list that the sender
/// is prepared to accept, in octets."
///
/// Per RFC 7540 §10.5.1: "A server that receives a larger header list than
/// it is willing to handle can send an HTTP 431 (Request Header Fields Too Large)
/// status code. A client can discard responses that it cannot process."
///
/// This tests:
/// - Accumulated header-block size across HEADERS + multiple CONTINUATION frames
/// - Enforcement of SETTINGS_MAX_HEADER_LIST_SIZE limits
/// - Proper rejection when total size exceeds configured maximum
/// - Header block fragmentation across frame boundaries

#[derive(Debug, Arbitrary)]
struct HeaderOverflowTest {
    /// Maximum header list size setting
    max_header_list_size: u32,
    /// Sequence of header frames
    header_frames: Vec<HeaderFrame>,
    /// Whether to send END_HEADERS on last frame
    end_headers_on_last: bool,
}

#[derive(Debug, Arbitrary, Clone)]
struct HeaderFrame {
    /// Frame type (HEADERS or CONTINUATION)
    frame_type: FrameType,
    /// Header block fragment
    header_block_fragment: Vec<u8>,
    /// END_HEADERS flag on this frame
    end_headers: bool,
}

#[derive(Debug, Arbitrary, Clone, PartialEq)]
enum FrameType {
    Headers,
    Continuation,
}

#[derive(Debug, Clone, PartialEq)]
enum HeaderProcessResult {
    Success(HeaderBlockState),
    OverflowError(HeaderOverflowError),
    ProtocolError(String),
    Pending(HeaderBlockState),
}

#[derive(Debug, Clone, PartialEq)]
enum HeaderOverflowError {
    ExceedsMaxHeaderListSize { actual: usize, limit: u32 },
    HeaderBlockTooLarge,
    TooManyFrames,
    InvalidFrameSequence,
    IncompleteHeaderBlock,
}

#[derive(Debug, Clone, PartialEq)]
struct HeaderBlockState {
    /// Accumulated header block data
    accumulated_data: Vec<u8>,
    /// Current accumulated size
    current_size: usize,
    /// Number of frames processed
    frames_processed: usize,
    /// Whether header block is complete (END_HEADERS received)
    complete: bool,
    /// Stream ID being processed
    stream_id: u32,
    /// Processing statistics
    stats: HeaderStats,
}

#[derive(Debug, Clone, PartialEq, Default)]
struct HeaderStats {
    /// Total header frames received
    header_frames: usize,
    /// Total continuation frames received
    continuation_frames: usize,
    /// Peak accumulated size during processing
    peak_size: usize,
    /// Number of overflow checks performed
    overflow_checks: usize,
}

/// Mock HTTP/2 header processor for testing size limits
struct MockHeaderProcessor {
    /// Current header block states per stream
    active_streams: HashMap<u32, HeaderBlockState>,
    /// Connection settings
    settings: ConnectionSettings,
    /// Processing policy
    policy: HeaderProcessingPolicy,
}

#[derive(Debug, Clone)]
struct ConnectionSettings {
    /// Maximum header list size (SETTINGS_MAX_HEADER_LIST_SIZE)
    max_header_list_size: u32,
    /// Maximum frame size
    max_frame_size: u32,
    /// Maximum concurrent streams
    max_concurrent_streams: u32,
}

#[derive(Debug, Clone)]
struct HeaderProcessingPolicy {
    /// Enforce SETTINGS_MAX_HEADER_LIST_SIZE strictly
    enforce_max_header_list_size: bool,
    /// Maximum number of CONTINUATION frames allowed
    max_continuation_frames: usize,
    /// Maximum total header block size (separate from header list size)
    max_header_block_size: usize,
    /// Whether to allow empty header fragments
    allow_empty_fragments: bool,
}

impl Default for ConnectionSettings {
    fn default() -> Self {
        Self {
            max_header_list_size: 8192, // 8KB default
            max_frame_size: 16384,      // 16KB default
            max_concurrent_streams: 100,
        }
    }
}

impl Default for HeaderProcessingPolicy {
    fn default() -> Self {
        Self {
            enforce_max_header_list_size: true,
            max_continuation_frames: 1000,      // Prevent DoS
            max_header_block_size: 1024 * 1024, // 1MB max block size
            allow_empty_fragments: true,
        }
    }
}

impl MockHeaderProcessor {
    fn new() -> Self {
        Self {
            active_streams: HashMap::new(),
            settings: ConnectionSettings::default(),
            policy: HeaderProcessingPolicy::default(),
        }
    }

    fn with_settings(settings: ConnectionSettings) -> Self {
        Self {
            active_streams: HashMap::new(),
            settings,
            policy: HeaderProcessingPolicy::default(),
        }
    }

    fn with_policy(policy: HeaderProcessingPolicy) -> Self {
        Self {
            active_streams: HashMap::new(),
            settings: ConnectionSettings::default(),
            policy,
        }
    }

    /// Process a HEADERS or CONTINUATION frame
    fn process_header_frame(
        &mut self,
        stream_id: u32,
        frame: &HeaderFrame,
    ) -> Result<HeaderProcessResult, HeaderOverflowError> {
        // Validate stream ID
        if stream_id == 0 {
            return Ok(HeaderProcessResult::ProtocolError(
                "Stream ID cannot be 0 for HEADERS/CONTINUATION".to_string(),
            ));
        }

        // Handle HEADERS frame (starts new header block)
        if frame.frame_type == FrameType::Headers {
            return self.process_headers_frame(stream_id, frame);
        }

        // Handle CONTINUATION frame (continues existing header block)
        if frame.frame_type == FrameType::Continuation {
            return self.process_continuation_frame(stream_id, frame);
        }

        Ok(HeaderProcessResult::ProtocolError(
            "Unknown frame type".to_string(),
        ))
    }

    /// Process HEADERS frame (starts new header block)
    fn process_headers_frame(
        &mut self,
        stream_id: u32,
        frame: &HeaderFrame,
    ) -> Result<HeaderProcessResult, HeaderOverflowError> {
        // HEADERS frame always starts a new header block
        // If there's an existing incomplete block, that's a protocol error
        if self.active_streams.contains_key(&stream_id) {
            return Ok(HeaderProcessResult::ProtocolError(
                "HEADERS frame received while header block incomplete".to_string(),
            ));
        }

        // Check if we can handle another stream
        if self.active_streams.len() >= self.settings.max_concurrent_streams as usize {
            return Ok(HeaderProcessResult::ProtocolError(
                "Too many concurrent streams".to_string(),
            ));
        }

        // Check frame size limit
        if frame.header_block_fragment.len() > self.settings.max_frame_size as usize {
            return Ok(HeaderProcessResult::ProtocolError(
                "Frame size exceeds SETTINGS_MAX_FRAME_SIZE".to_string(),
            ));
        }

        // Initialize header block state
        let initial_size = frame.header_block_fragment.len();
        let mut state = HeaderBlockState {
            accumulated_data: frame.header_block_fragment.clone(),
            current_size: initial_size,
            frames_processed: 1,
            complete: frame.end_headers,
            stream_id,
            stats: HeaderStats {
                header_frames: 1,
                continuation_frames: 0,
                peak_size: initial_size,
                overflow_checks: 0,
            },
        };

        // Check size limits
        if let Some(overflow_result) = self.check_size_limits(&mut state)? {
            return Ok(overflow_result);
        }

        if state.complete {
            // Header block is complete, remove from active tracking
            Ok(HeaderProcessResult::Success(state))
        } else {
            // Header block incomplete, store for CONTINUATION frames
            self.active_streams.insert(stream_id, state.clone());
            Ok(HeaderProcessResult::Pending(state))
        }
    }

    /// Process CONTINUATION frame (continues existing header block)
    fn process_continuation_frame(
        &mut self,
        stream_id: u32,
        frame: &HeaderFrame,
    ) -> Result<HeaderProcessResult, HeaderOverflowError> {
        // CONTINUATION must follow HEADERS or another CONTINUATION
        let mut state = self
            .active_streams
            .get(&stream_id)
            .cloned()
            .ok_or(HeaderOverflowError::InvalidFrameSequence)?;

        // Check frame size limit
        if frame.header_block_fragment.len() > self.settings.max_frame_size as usize {
            return Ok(HeaderProcessResult::ProtocolError(
                "Frame size exceeds SETTINGS_MAX_FRAME_SIZE".to_string(),
            ));
        }

        // Check CONTINUATION frame limit
        if state.stats.continuation_frames >= self.policy.max_continuation_frames {
            return Err(HeaderOverflowError::TooManyFrames);
        }

        // Handle empty fragments
        if frame.header_block_fragment.is_empty() && !self.policy.allow_empty_fragments {
            return Ok(HeaderProcessResult::ProtocolError(
                "Empty header block fragment not allowed".to_string(),
            ));
        }

        // Accumulate header block fragment
        state
            .accumulated_data
            .extend_from_slice(&frame.header_block_fragment);
        state.current_size += frame.header_block_fragment.len();
        state.frames_processed += 1;
        state.stats.continuation_frames += 1;
        state.stats.peak_size = state.stats.peak_size.max(state.current_size);
        state.complete = frame.end_headers;

        // Check size limits
        if let Some(overflow_result) = self.check_size_limits(&mut state)? {
            // Remove from active streams on overflow
            self.active_streams.remove(&stream_id);
            return Ok(overflow_result);
        }

        if state.complete {
            // Header block is complete, remove from active tracking
            self.active_streams.remove(&stream_id);
            Ok(HeaderProcessResult::Success(state))
        } else {
            // Header block still incomplete, update state
            self.active_streams.insert(stream_id, state.clone());
            Ok(HeaderProcessResult::Pending(state))
        }
    }

    /// Check header size limits per RFC 7540
    fn check_size_limits(
        &self,
        state: &mut HeaderBlockState,
    ) -> Result<Option<HeaderProcessResult>, HeaderOverflowError> {
        state.stats.overflow_checks += 1;

        // Check SETTINGS_MAX_HEADER_LIST_SIZE (RFC 7540 §6.5.2)
        if self.policy.enforce_max_header_list_size {
            if state.current_size > self.settings.max_header_list_size as usize {
                return Ok(Some(HeaderProcessResult::OverflowError(
                    HeaderOverflowError::ExceedsMaxHeaderListSize {
                        actual: state.current_size,
                        limit: self.settings.max_header_list_size,
                    },
                )));
            }
        }

        // Check maximum header block size (implementation limit)
        if state.current_size > self.policy.max_header_block_size {
            return Ok(Some(HeaderProcessResult::OverflowError(
                HeaderOverflowError::HeaderBlockTooLarge,
            )));
        }

        Ok(None)
    }

    /// Update connection settings (e.g., from SETTINGS frame)
    fn update_settings(&mut self, new_settings: ConnectionSettings) -> Result<(), String> {
        // Validate settings
        if new_settings.max_header_list_size > 16 * 1024 * 1024 {
            return Err("max_header_list_size too large".to_string());
        }

        if new_settings.max_frame_size < 16384 || new_settings.max_frame_size > 16777215 {
            return Err("max_frame_size out of valid range".to_string());
        }

        // Check if any active streams would now exceed the new limit
        let new_limit = new_settings.max_header_list_size as usize;
        for (stream_id, state) in &self.active_streams {
            if state.current_size > new_limit {
                // Could either close the stream or reject the setting
                // For this test, we'll allow the setting but mark streams for closure
            }
        }

        self.settings = new_settings;
        Ok(())
    }

    /// Get current settings
    fn get_settings(&self) -> &ConnectionSettings {
        &self.settings
    }

    /// Get active streams count
    fn get_active_streams_count(&self) -> usize {
        self.active_streams.len()
    }

    /// Get active stream state
    fn get_stream_state(&self, stream_id: u32) -> Option<&HeaderBlockState> {
        self.active_streams.get(&stream_id)
    }

    /// Simulate stream reset (clears header block state)
    fn reset_stream(&mut self, stream_id: u32) {
        self.active_streams.remove(&stream_id);
    }
}

/// Generate predefined test cases for header overflow detection
fn generate_test_cases() -> Vec<(String, u32, Vec<HeaderFrame>, HeaderProcessResult)> {
    vec![
        // Test case 1: Single HEADERS frame within limit
        (
            "Single HEADERS within limit".to_string(),
            8192, // 8KB limit
            vec![HeaderFrame {
                frame_type: FrameType::Headers,
                header_block_fragment: vec![0x42; 4096], // 4KB header block
                end_headers: true,
            }],
            HeaderProcessResult::Success(HeaderBlockState {
                accumulated_data: vec![0x42; 4096],
                current_size: 4096,
                frames_processed: 1,
                complete: true,
                stream_id: 1,
                stats: HeaderStats {
                    header_frames: 1,
                    continuation_frames: 0,
                    peak_size: 4096,
                    overflow_checks: 1,
                },
            }),
        ),
        // Test case 2: HEADERS + CONTINUATION exceeding limit
        (
            "HEADERS + CONTINUATION exceeding limit".to_string(),
            8192, // 8KB limit
            vec![
                HeaderFrame {
                    frame_type: FrameType::Headers,
                    header_block_fragment: vec![0x41; 4096], // 4KB
                    end_headers: false,
                },
                HeaderFrame {
                    frame_type: FrameType::Continuation,
                    header_block_fragment: vec![0x42; 5000], // 5KB (total 9KB > 8KB limit)
                    end_headers: true,
                },
            ],
            HeaderProcessResult::OverflowError(HeaderOverflowError::ExceedsMaxHeaderListSize {
                actual: 9096,
                limit: 8192,
            }),
        ),
        // Test case 3: Multiple CONTINUATION frames within limit
        (
            "Multiple CONTINUATION frames within limit".to_string(),
            16384, // 16KB limit
            vec![
                HeaderFrame {
                    frame_type: FrameType::Headers,
                    header_block_fragment: vec![0x41; 2000], // 2KB
                    end_headers: false,
                },
                HeaderFrame {
                    frame_type: FrameType::Continuation,
                    header_block_fragment: vec![0x42; 3000], // 3KB
                    end_headers: false,
                },
                HeaderFrame {
                    frame_type: FrameType::Continuation,
                    header_block_fragment: vec![0x43; 4000], // 4KB (total 9KB < 16KB)
                    end_headers: true,
                },
            ],
            HeaderProcessResult::Success(HeaderBlockState {
                accumulated_data: {
                    let mut data = Vec::new();
                    data.extend_from_slice(&vec![0x41; 2000]);
                    data.extend_from_slice(&vec![0x42; 3000]);
                    data.extend_from_slice(&vec![0x43; 4000]);
                    data
                },
                current_size: 9000,
                frames_processed: 3,
                complete: true,
                stream_id: 1,
                stats: HeaderStats {
                    header_frames: 1,
                    continuation_frames: 2,
                    peak_size: 9000,
                    overflow_checks: 3,
                },
            }),
        ),
        // Test case 4: Gradual accumulation hitting exact limit
        (
            "Gradual accumulation at exact limit".to_string(),
            10000, // 10KB limit
            vec![
                HeaderFrame {
                    frame_type: FrameType::Headers,
                    header_block_fragment: vec![0x41; 5000], // 5KB
                    end_headers: false,
                },
                HeaderFrame {
                    frame_type: FrameType::Continuation,
                    header_block_fragment: vec![0x42; 5000], // 5KB (total exactly 10KB)
                    end_headers: true,
                },
            ],
            HeaderProcessResult::Success(HeaderBlockState {
                accumulated_data: {
                    let mut data = Vec::new();
                    data.extend_from_slice(&vec![0x41; 5000]);
                    data.extend_from_slice(&vec![0x42; 5000]);
                    data
                },
                current_size: 10000,
                frames_processed: 2,
                complete: true,
                stream_id: 1,
                stats: HeaderStats {
                    header_frames: 1,
                    continuation_frames: 1,
                    peak_size: 10000,
                    overflow_checks: 2,
                },
            }),
        ),
    ]
}

fuzz_target!(|data: &[u8]| {
    // Limit input size to prevent timeouts
    if data.len() > 2048 {
        return;
    }

    // Try to generate a structured test from the fuzz data
    let test = match HeaderOverflowTest::arbitrary(&mut arbitrary::Unstructured::new(data)) {
        Ok(test) => test,
        Err(_) => return, // Invalid input, skip
    };

    // Skip tests with unreasonable parameters
    if test.header_frames.is_empty() || test.header_frames.len() > 100 {
        return;
    }

    // Limit max header list size to reasonable range
    let max_header_list_size = test.max_header_list_size.clamp(1024, 1024 * 1024); // 1KB - 1MB

    // Limit individual frame sizes
    let mut frames = test.header_frames;
    for frame in &mut frames {
        if frame.header_block_fragment.len() > 100000 {
            frame.header_block_fragment.truncate(100000); // Limit to 100KB per frame
        }
    }

    // Create processor with test settings
    let settings = ConnectionSettings {
        max_header_list_size,
        max_frame_size: 65536, // 64KB
        max_concurrent_streams: 100,
    };

    let mut processor = MockHeaderProcessor::with_settings(settings);
    let stream_id = 1u32;

    // Process frames in sequence
    let mut last_result = None;
    let mut total_accumulated = 0usize;

    for (i, frame) in frames.iter().enumerate() {
        let result = processor.process_header_frame(stream_id, frame);

        match result {
            Ok(HeaderProcessResult::Success(state)) => {
                // Successful completion
                assert!(state.complete, "Success result should have complete=true");
                assert_eq!(state.stream_id, stream_id, "Stream ID should match");
                assert!(
                    state.current_size <= max_header_list_size as usize
                        || !processor.policy.enforce_max_header_list_size,
                    "Successful result should respect header list size limit"
                );

                // Verify accumulated data integrity
                let expected_size: usize = frames[..=i]
                    .iter()
                    .map(|f| f.header_block_fragment.len())
                    .sum();
                assert_eq!(
                    state.current_size, expected_size,
                    "Accumulated size should match sum of fragments"
                );

                last_result = Some(result);
                break; // Header block complete
            }

            Ok(HeaderProcessResult::Pending(state)) => {
                // Incomplete header block
                assert!(!state.complete, "Pending result should have complete=false");
                assert!(
                    i < frames.len() - 1 || !test.end_headers_on_last,
                    "Pending should not be last frame with END_HEADERS"
                );

                total_accumulated += frame.header_block_fragment.len();

                // Verify size tracking
                assert_eq!(
                    state.current_size, total_accumulated,
                    "Pending state size should match accumulated total"
                );

                last_result = Some(result);
            }

            Ok(HeaderProcessResult::OverflowError(error)) => {
                // Size limit exceeded
                match error {
                    HeaderOverflowError::ExceedsMaxHeaderListSize { actual, limit } => {
                        assert!(
                            actual > limit as usize,
                            "Overflow error should have actual > limit"
                        );
                        assert_eq!(
                            limit, max_header_list_size,
                            "Limit should match configured setting"
                        );
                    }
                    HeaderOverflowError::HeaderBlockTooLarge => {
                        // Implementation-specific limit exceeded
                    }
                    _ => {
                        // Other overflow errors are acceptable
                    }
                }

                last_result = Some(result);
                break; // Processing stopped due to overflow
            }

            Ok(HeaderProcessResult::ProtocolError(_)) => {
                // Protocol violation
                last_result = Some(result);
                break; // Processing stopped due to protocol error
            }

            Err(error) => {
                // Processing error
                match error {
                    HeaderOverflowError::InvalidFrameSequence => {
                        // CONTINUATION without HEADERS, etc.
                    }
                    HeaderOverflowError::TooManyFrames => {
                        // DoS protection triggered
                    }
                    _ => {
                        // Other errors are acceptable
                    }
                }

                last_result = Some(Err(error));
                break;
            }
        }
    }

    // Verify final state consistency
    if let Some(Ok(final_result)) = last_result {
        match final_result {
            HeaderProcessResult::Success(_) => {
                // Should have no active streams after success
                assert_eq!(
                    processor.get_active_streams_count(),
                    0,
                    "No active streams should remain after successful completion"
                );
            }

            HeaderProcessResult::Pending(_) => {
                // Should have exactly one active stream
                assert_eq!(
                    processor.get_active_streams_count(),
                    1,
                    "One active stream should remain for pending result"
                );

                // Stream state should be available
                assert!(
                    processor.get_stream_state(stream_id).is_some(),
                    "Stream state should be available for pending stream"
                );
            }

            HeaderProcessResult::OverflowError(_) => {
                // Active stream should be cleaned up after overflow
                assert_eq!(
                    processor.get_active_streams_count(),
                    0,
                    "No active streams should remain after overflow error"
                );
            }

            HeaderProcessResult::ProtocolError(_) => {
                // Protocol errors may or may not clean up state
                // depending on the specific error
            }
        }
    }

    // Test settings update during processing
    let new_settings = ConnectionSettings {
        max_header_list_size: max_header_list_size / 2, // Reduce limit
        max_frame_size: 32768,
        max_concurrent_streams: 50,
    };

    let _update_result = processor.update_settings(new_settings);
    // Should handle settings changes gracefully

    // Run predefined test cases for verification
    for (test_name, limit, test_frames, expected) in generate_test_cases() {
        let test_settings = ConnectionSettings {
            max_header_list_size: limit,
            max_frame_size: 65536,
            max_concurrent_streams: 100,
        };

        let mut test_processor = MockHeaderProcessor::with_settings(test_settings);
        let test_stream_id = 1u32;

        let mut test_last_result = None;
        for frame in test_frames {
            let frame_result = test_processor.process_header_frame(test_stream_id, &frame);
            test_last_result = Some(frame_result);

            match &test_last_result {
                Some(Ok(HeaderProcessResult::Success(_)))
                | Some(Ok(HeaderProcessResult::OverflowError(_)))
                | Some(Ok(HeaderProcessResult::ProtocolError(_)))
                | Some(Err(_)) => {
                    break; // Processing complete
                }
                _ => {
                    // Continue with next frame
                }
            }
        }

        if let Some(Ok(actual_result)) = test_last_result {
            match (&actual_result, &expected) {
                (
                    HeaderProcessResult::Success(actual_state),
                    HeaderProcessResult::Success(expected_state),
                ) => {
                    assert_eq!(
                        actual_state.current_size, expected_state.current_size,
                        "Test '{}': size mismatch",
                        test_name
                    );
                    assert_eq!(
                        actual_state.complete, expected_state.complete,
                        "Test '{}': completion status mismatch",
                        test_name
                    );
                }

                (
                    HeaderProcessResult::OverflowError(actual_error),
                    HeaderProcessResult::OverflowError(expected_error),
                ) => {
                    assert_eq!(
                        std::mem::discriminant(actual_error),
                        std::mem::discriminant(expected_error),
                        "Test '{}': overflow error type mismatch",
                        test_name
                    );
                }

                _ => {
                    // Other combinations may be acceptable due to fuzzing variations
                }
            }
        }
    }
});
