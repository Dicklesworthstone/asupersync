//! Fuzzing target for HTTP/2 HEADERS+CONTINUATION frame sequencing.
//!
//! Tests RFC 9113 compliance for header block fragmentation across multiple frames:
//! 1. HEADERS frame starts sequence (may have END_HEADERS=false)
//! 2. CONTINUATION frames continue the sequence
//! 3. Only final frame should have END_HEADERS=true
//! 4. No other frame types allowed between HEADERS and CONTINUATION
//! 5. All frames must have same stream ID
//! 6. Timeout handling for incomplete sequences
//!
//! Vulnerability areas:
//! - Interleaved frame types breaking the sequence
//! - Stream ID mismatches in continuation chain
//! - Multiple END_HEADERS flags
//! - Missing END_HEADERS causing timeouts
//! - State corruption from abandoned sequences

#![no_main]

use libfuzzer_sys::fuzz_target;
use arbitrary::Arbitrary;

/// Mock HTTP/2 connection for testing HEADERS+CONTINUATION sequencing.
#[derive(Debug, Clone)]
pub struct MockH2Connection {
    /// Current continuation state
    continuation_state: Option<ContinuationState>,
    /// Stream states for tracking header completion
    streams: std::collections::HashMap<u32, StreamHeaderState>,
    /// Sequence violations detected
    violations: Vec<SequenceViolation>,
    /// Configuration for timeout and limits
    config: SequencingConfig,
}

/// State tracking for continuation sequences
#[derive(Debug, Clone)]
pub struct ContinuationState {
    /// Stream ID being continued
    pub stream_id: u32,
    /// Frame type that started the sequence (Headers or PushPromise)
    pub initiating_frame: InitiatingFrameType,
    /// Number of frames in the sequence so far
    pub frame_count: u32,
    /// Total header block size accumulated
    pub accumulated_size: usize,
    /// Mock timestamp when sequence started
    pub started_at: u64,
}

/// State of header processing for a stream
#[derive(Debug, Clone)]
pub struct StreamHeaderState {
    /// Whether the stream has completed headers
    pub headers_complete: bool,
    /// Total header block size
    pub total_header_size: usize,
    /// Number of header fragments received
    pub fragment_count: u32,
}

/// Types of frames that can initiate continuation sequences
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InitiatingFrameType {
    Headers,
    PushPromise,
}

/// Configuration for sequencing validation
#[derive(Debug, Clone)]
pub struct SequencingConfig {
    /// Maximum time allowed for continuation sequences (mock milliseconds)
    pub continuation_timeout_ms: u64,
    /// Maximum header block size
    pub max_header_size: usize,
    /// Maximum number of continuation frames
    pub max_continuation_frames: u32,
}

/// Types of sequencing violations
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SequenceViolation {
    /// Frame received while expecting CONTINUATION
    InterveningFrame {
        expected_stream: u32,
        received_frame_type: MockFrameType,
        received_stream: u32,
    },
    /// CONTINUATION frame for wrong stream ID
    ContinuationStreamMismatch {
        expected_stream: u32,
        received_stream: u32
    },
    /// CONTINUATION frame without a preceding HEADERS/PUSH_PROMISE
    UnexpectedContinuation {
        stream_id: u32
    },
    /// Multiple frames with END_HEADERS=true in same sequence
    MultipleEndHeaders {
        stream_id: u32,
        frame_number: u32
    },
    /// Continuation sequence timed out
    ContinuationTimeout {
        stream_id: u32,
        duration_ms: u64
    },
    /// Header block size exceeded limit
    HeaderBlockTooLarge {
        stream_id: u32,
        size: usize,
        limit: usize
    },
    /// Too many continuation frames
    TooManyContinuationFrames {
        stream_id: u32,
        count: u32,
        limit: u32
    },
    /// END_HEADERS=false on final allowable frame
    MissingEndHeaders {
        stream_id: u32
    },
}

/// Mock frame types for testing
#[derive(Debug, Clone, PartialEq, Eq, Arbitrary)]
pub enum MockFrameType {
    Headers,
    Continuation,
    Data,
    RstStream,
    Settings,
    PushPromise,
    Ping,
    GoAway,
    WindowUpdate,
}

/// Mock HTTP/2 frame for sequencing tests
#[derive(Debug, Clone, Arbitrary)]
pub struct MockFrame {
    /// Frame type
    pub frame_type: MockFrameType,
    /// Stream ID
    pub stream_id: u32,
    /// Whether this frame has END_HEADERS flag (for applicable frame types)
    pub end_headers: bool,
    /// Whether this frame has END_STREAM flag (for applicable frame types)
    pub end_stream: bool,
    /// Mock header block size for this frame
    pub header_block_size: u16,
    /// Mock timestamp for timeout testing
    pub timestamp: u64,
}

/// Frame sequence test scenario
#[derive(Debug, Clone, Arbitrary)]
pub struct HeadersContinuationScenario {
    /// Sequence of frames to process
    pub frames: Vec<MockFrame>,
    /// Whether to test timeout scenarios
    pub enable_timeout_testing: bool,
    /// Maximum frames to prevent infinite loops
    pub max_frames: u8,
}

impl Default for SequencingConfig {
    fn default() -> Self {
        Self {
            continuation_timeout_ms: 5000,
            max_header_size: 65536,
            max_continuation_frames: 100,
        }
    }
}

impl MockH2Connection {
    pub fn new(config: SequencingConfig) -> Self {
        Self {
            continuation_state: None,
            streams: std::collections::HashMap::new(),
            violations: Vec::new(),
            config,
        }
    }

    /// Process a frame and validate sequencing rules
    pub fn process_frame(&mut self, frame: MockFrame) -> FrameProcessingResult {
        // Check for continuation timeout if we're in a continuation sequence
        if let Some(ref state) = self.continuation_state {
            let duration = frame.timestamp.saturating_sub(state.started_at);
            if duration > self.config.continuation_timeout_ms {
                self.violations.push(SequenceViolation::ContinuationTimeout {
                    stream_id: state.stream_id,
                    duration_ms: duration,
                });
                self.continuation_state = None;
                return FrameProcessingResult::TimeoutViolation;
            }
        }

        match frame.frame_type {
            MockFrameType::Headers => self.process_headers_frame(frame),
            MockFrameType::Continuation => self.process_continuation_frame(frame),
            MockFrameType::PushPromise => self.process_push_promise_frame(frame),
            _ => self.process_other_frame(frame),
        }
    }

    fn process_headers_frame(&mut self, frame: MockFrame) -> FrameProcessingResult {
        // Check if we're already expecting a continuation
        if let Some(ref state) = self.continuation_state {
            self.violations.push(SequenceViolation::InterveningFrame {
                expected_stream: state.stream_id,
                received_frame_type: frame.frame_type,
                received_stream: frame.stream_id,
            });
            return FrameProcessingResult::SequenceViolation;
        }

        let stream_state = self.streams.entry(frame.stream_id)
            .or_insert_with(|| StreamHeaderState {
                headers_complete: false,
                total_header_size: 0,
                fragment_count: 0,
            });

        stream_state.total_header_size += frame.header_block_size as usize;
        stream_state.fragment_count += 1;

        // Check header size limit
        if stream_state.total_header_size > self.config.max_header_size {
            self.violations.push(SequenceViolation::HeaderBlockTooLarge {
                stream_id: frame.stream_id,
                size: stream_state.total_header_size,
                limit: self.config.max_header_size,
            });
            return FrameProcessingResult::HeaderTooLarge;
        }

        if frame.end_headers {
            // Complete header block
            stream_state.headers_complete = true;
            FrameProcessingResult::HeadersComplete
        } else {
            // Start continuation sequence
            self.continuation_state = Some(ContinuationState {
                stream_id: frame.stream_id,
                initiating_frame: InitiatingFrameType::Headers,
                frame_count: 1,
                accumulated_size: frame.header_block_size as usize,
                started_at: frame.timestamp,
            });
            FrameProcessingResult::ContinuationStarted
        }
    }

    fn process_continuation_frame(&mut self, frame: MockFrame) -> FrameProcessingResult {
        let state = match &mut self.continuation_state {
            Some(state) => state,
            None => {
                self.violations.push(SequenceViolation::UnexpectedContinuation {
                    stream_id: frame.stream_id,
                });
                return FrameProcessingResult::UnexpectedFrame;
            }
        };

        // Verify stream ID matches
        if frame.stream_id != state.stream_id {
            self.violations.push(SequenceViolation::ContinuationStreamMismatch {
                expected_stream: state.stream_id,
                received_stream: frame.stream_id,
            });
            return FrameProcessingResult::StreamMismatch;
        }

        // Update state
        state.frame_count += 1;
        state.accumulated_size += frame.header_block_size as usize;

        // Check frame count limit
        if state.frame_count > self.config.max_continuation_frames {
            self.violations.push(SequenceViolation::TooManyContinuationFrames {
                stream_id: frame.stream_id,
                count: state.frame_count,
                limit: self.config.max_continuation_frames,
            });
            return FrameProcessingResult::TooManyFrames;
        }

        // Update stream state
        let stream_state = self.streams.get_mut(&frame.stream_id).unwrap();
        stream_state.total_header_size += frame.header_block_size as usize;
        stream_state.fragment_count += 1;

        // Check header size limit
        if stream_state.total_header_size > self.config.max_header_size {
            self.violations.push(SequenceViolation::HeaderBlockTooLarge {
                stream_id: frame.stream_id,
                size: stream_state.total_header_size,
                limit: self.config.max_header_size,
            });
            return FrameProcessingResult::HeaderTooLarge;
        }

        if frame.end_headers {
            // Complete the continuation sequence
            stream_state.headers_complete = true;
            self.continuation_state = None;
            FrameProcessingResult::ContinuationComplete
        } else {
            // Check if we're at the frame limit but haven't ended
            if state.frame_count >= self.config.max_continuation_frames {
                self.violations.push(SequenceViolation::MissingEndHeaders {
                    stream_id: frame.stream_id,
                });
                return FrameProcessingResult::MissingEndHeaders;
            }
            FrameProcessingResult::ContinuationContinued
        }
    }

    fn process_push_promise_frame(&mut self, frame: MockFrame) -> FrameProcessingResult {
        // Similar logic to HEADERS but for PUSH_PROMISE
        if let Some(ref state) = self.continuation_state {
            self.violations.push(SequenceViolation::InterveningFrame {
                expected_stream: state.stream_id,
                received_frame_type: frame.frame_type,
                received_stream: frame.stream_id,
            });
            return FrameProcessingResult::SequenceViolation;
        }

        if frame.end_headers {
            FrameProcessingResult::PushPromiseComplete
        } else {
            self.continuation_state = Some(ContinuationState {
                stream_id: frame.stream_id,
                initiating_frame: InitiatingFrameType::PushPromise,
                frame_count: 1,
                accumulated_size: frame.header_block_size as usize,
                started_at: frame.timestamp,
            });
            FrameProcessingResult::ContinuationStarted
        }
    }

    fn process_other_frame(&mut self, frame: MockFrame) -> FrameProcessingResult {
        // Check if we're expecting a continuation
        if let Some(ref state) = self.continuation_state {
            self.violations.push(SequenceViolation::InterveningFrame {
                expected_stream: state.stream_id,
                received_frame_type: frame.frame_type,
                received_stream: frame.stream_id,
            });
            return FrameProcessingResult::SequenceViolation;
        }

        // Regular frame processing (no sequencing issues)
        FrameProcessingResult::RegularFrame
    }

    /// Get sequencing violations
    pub fn violations(&self) -> &[SequenceViolation] {
        &self.violations
    }

    /// Check if currently expecting continuation
    pub fn expecting_continuation(&self) -> bool {
        self.continuation_state.is_some()
    }

    /// Get current continuation stream ID if any
    pub fn continuation_stream_id(&self) -> Option<u32> {
        self.continuation_state.as_ref().map(|s| s.stream_id)
    }
}

/// Result of processing a frame
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FrameProcessingResult {
    HeadersComplete,
    ContinuationStarted,
    ContinuationContinued,
    ContinuationComplete,
    PushPromiseComplete,
    RegularFrame,
    SequenceViolation,
    UnexpectedFrame,
    StreamMismatch,
    TimeoutViolation,
    HeaderTooLarge,
    TooManyFrames,
    MissingEndHeaders,
}

/// Test specific continuation sequence patterns
fn test_valid_headers_continuation_sequence() {
    let mut conn = MockH2Connection::new(SequencingConfig::default());

    // HEADERS frame without END_HEADERS
    let headers_frame = MockFrame {
        frame_type: MockFrameType::Headers,
        stream_id: 1,
        end_headers: false,
        end_stream: false,
        header_block_size: 1000,
        timestamp: 0,
    };

    let result = conn.process_frame(headers_frame);
    assert_eq!(result, FrameProcessingResult::ContinuationStarted);
    assert!(conn.expecting_continuation());
    assert_eq!(conn.continuation_stream_id(), Some(1));

    // CONTINUATION frame continuing the sequence
    let continuation1 = MockFrame {
        frame_type: MockFrameType::Continuation,
        stream_id: 1,
        end_headers: false,
        end_stream: false,
        header_block_size: 500,
        timestamp: 100,
    };

    let result = conn.process_frame(continuation1);
    assert_eq!(result, FrameProcessingResult::ContinuationContinued);
    assert!(conn.expecting_continuation());

    // Final CONTINUATION frame with END_HEADERS
    let continuation2 = MockFrame {
        frame_type: MockFrameType::Continuation,
        stream_id: 1,
        end_headers: true,
        end_stream: false,
        header_block_size: 200,
        timestamp: 200,
    };

    let result = conn.process_frame(continuation2);
    assert_eq!(result, FrameProcessingResult::ContinuationComplete);
    assert!(!conn.expecting_continuation());
    assert_eq!(conn.violations().len(), 0);
}

/// Test intervening frame violation
fn test_intervening_frame_violation() {
    let mut conn = MockH2Connection::new(SequencingConfig::default());

    // Start HEADERS without END_HEADERS
    let headers_frame = MockFrame {
        frame_type: MockFrameType::Headers,
        stream_id: 1,
        end_headers: false,
        end_stream: false,
        header_block_size: 1000,
        timestamp: 0,
    };

    conn.process_frame(headers_frame);
    assert!(conn.expecting_continuation());

    // Send intervening DATA frame (violation)
    let data_frame = MockFrame {
        frame_type: MockFrameType::Data,
        stream_id: 1,
        end_headers: false,
        end_stream: false,
        header_block_size: 0,
        timestamp: 100,
    };

    let result = conn.process_frame(data_frame);
    assert_eq!(result, FrameProcessingResult::SequenceViolation);

    // Check violation was recorded
    let violations = conn.violations();
    assert_eq!(violations.len(), 1);
    assert!(matches!(violations[0], SequenceViolation::InterveningFrame { .. }));
}

/// Test stream ID mismatch in continuation
fn test_continuation_stream_mismatch() {
    let mut conn = MockH2Connection::new(SequencingConfig::default());

    // Start HEADERS on stream 1
    let headers_frame = MockFrame {
        frame_type: MockFrameType::Headers,
        stream_id: 1,
        end_headers: false,
        end_stream: false,
        header_block_size: 1000,
        timestamp: 0,
    };

    conn.process_frame(headers_frame);

    // Send CONTINUATION on wrong stream (violation)
    let continuation_frame = MockFrame {
        frame_type: MockFrameType::Continuation,
        stream_id: 3, // Wrong stream!
        end_headers: true,
        end_stream: false,
        header_block_size: 500,
        timestamp: 100,
    };

    let result = conn.process_frame(continuation_frame);
    assert_eq!(result, FrameProcessingResult::StreamMismatch);

    // Check violation
    let violations = conn.violations();
    assert_eq!(violations.len(), 1);
    assert!(matches!(violations[0], SequenceViolation::ContinuationStreamMismatch { .. }));
}

/// Test timeout handling
fn test_continuation_timeout() {
    let mut conn = MockH2Connection::new(SequencingConfig {
        continuation_timeout_ms: 1000,
        ..SequencingConfig::default()
    });

    // Start HEADERS sequence
    let headers_frame = MockFrame {
        frame_type: MockFrameType::Headers,
        stream_id: 1,
        end_headers: false,
        end_stream: false,
        header_block_size: 1000,
        timestamp: 0,
    };

    conn.process_frame(headers_frame);

    // Send CONTINUATION after timeout
    let late_continuation = MockFrame {
        frame_type: MockFrameType::Continuation,
        stream_id: 1,
        end_headers: true,
        end_stream: false,
        header_block_size: 500,
        timestamp: 2000, // Past the 1000ms timeout
    };

    let result = conn.process_frame(late_continuation);
    assert_eq!(result, FrameProcessingResult::TimeoutViolation);

    // Check timeout violation
    let violations = conn.violations();
    assert_eq!(violations.len(), 1);
    assert!(matches!(violations[0], SequenceViolation::ContinuationTimeout { .. }));
}

fuzz_target!(|scenario: HeadersContinuationScenario| {
    // Limit frames to prevent timeouts
    let max_frames = scenario.max_frames.min(100);
    let limited_frames: Vec<MockFrame> = scenario.frames
        .into_iter()
        .take(max_frames as usize)
        .collect();

    if limited_frames.is_empty() {
        return;
    }

    let mut config = SequencingConfig::default();
    if scenario.enable_timeout_testing {
        config.continuation_timeout_ms = 1000; // Shorter timeout for testing
    }

    let timeout_ms = config.continuation_timeout_ms;
    let mut conn = MockH2Connection::new(config);
    let mut results = Vec::new();

    // Process the frame sequence
    for frame in &limited_frames {
        let result = conn.process_frame(frame.clone());
        results.push(result.clone());

        // Early termination on certain violations to prevent cascading effects
        match result {
            FrameProcessingResult::TimeoutViolation |
            FrameProcessingResult::HeaderTooLarge |
            FrameProcessingResult::TooManyFrames => {
                break;
            }
            _ => {}
        }
    }

    // Validate final state consistency
    let violations = conn.violations();

    // Test invariants
    for violation in violations {
        match violation {
            SequenceViolation::InterveningFrame { expected_stream, received_stream, .. } => {
                // If expecting continuation on one stream, any other frame is a violation
                if expected_stream != received_stream {
                    // This is expected - different streams can't interleave continuation sequences
                }
            }
            SequenceViolation::ContinuationStreamMismatch { expected_stream, received_stream } => {
                // Stream ID must match in continuation sequence
                assert_ne!(expected_stream, received_stream);
            }
            SequenceViolation::UnexpectedContinuation { .. } => {
                // CONTINUATION without preceding HEADERS/PUSH_PROMISE
                // This should not crash the connection, just be rejected
            }
            SequenceViolation::ContinuationTimeout { duration_ms, .. } => {
                // Timeout should be properly detected
                assert!(*duration_ms > timeout_ms);
            }
            SequenceViolation::HeaderBlockTooLarge { size, limit, .. } => {
                // Size limit should be enforced
                assert!(size > limit);
            }
            _ => {
                // Other violations are also valid test cases
            }
        }
    }

    // Run targeted tests periodically
    if limited_frames.len() == 1 {
        test_valid_headers_continuation_sequence();
        test_intervening_frame_violation();
        test_continuation_stream_mismatch();
        test_continuation_timeout();
    }
});