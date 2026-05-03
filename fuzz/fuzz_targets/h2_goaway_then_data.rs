//! Fuzzing target for HTTP/2 GOAWAY frame followed by DATA frames.
//!
//! Tests RFC 7540 §6.8 compliance for frame processing after GOAWAY:
//! 1. GOAWAY frame specifies last-stream-id=N
//! 2. DATA frames on stream-id > N must be silently discarded
//! 3. DATA frames on stream-id <= N must still be processed normally
//! 4. Connection should not close until all streams <= N are complete
//! 5. New streams with ID > N must be rejected
//! 6. Multiple GOAWAY frames (last-stream-id must be monotonically decreasing)
//!
//! Vulnerability areas:
//! - Failing to discard DATA on streams beyond last-stream-id
//! - Processing DATA frames that should be ignored after GOAWAY
//! - Connection state corruption when mixing valid/invalid stream traffic
//! - Memory leaks from not cleaning up discarded frame data
//! - Last-stream-id validation and monotonic decrease enforcement
//! - Race conditions between GOAWAY processing and concurrent DATA frames

#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use std::collections::HashMap;

/// Mock HTTP/2 connection for testing GOAWAY + DATA frame interactions.
#[derive(Debug, Clone)]
pub struct MockGoAwayConnection {
    /// Current GOAWAY state
    pub goaway_state: Option<GoAwayState>,
    /// Stream states for tracking processing
    pub streams: HashMap<u32, StreamState>,
    /// Frames processed after GOAWAY
    pub processed_frames: Vec<ProcessedFrame>,
    /// Frames that should have been discarded
    pub discarded_frames: Vec<DiscardedFrame>,
    /// Violations detected during processing
    pub violations: Vec<GoAwayViolation>,
    /// Configuration for testing
    pub config: GoAwayConfig,
    /// Total DATA bytes processed (for verification)
    pub total_bytes_processed: u64,
    /// Total DATA bytes discarded (for verification)
    pub total_bytes_discarded: u64,
}

/// GOAWAY frame state
#[derive(Debug, Clone)]
pub struct GoAwayState {
    /// Last stream ID that will be processed
    pub last_stream_id: u32,
    /// Error code sent in GOAWAY
    pub error_code: u32,
    /// When the GOAWAY was received (mock timestamp)
    pub received_at: u64,
    /// Whether connection is in graceful shutdown mode
    pub graceful_shutdown: bool,
    /// Number of GOAWAY frames received (should be monotonic)
    pub goaway_count: u32,
}

/// Stream processing states
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StreamState {
    /// Stream is idle (not opened yet)
    Idle,
    /// Stream is open and accepting DATA
    Open,
    /// Stream has received END_STREAM but not fully processed
    HalfClosedRemote,
    /// Stream is fully closed
    Closed,
    /// Stream was reset
    Reset,
    /// Stream should be discarded (ID > last_stream_id after GOAWAY)
    Discarded,
}

/// Configuration for GOAWAY handling
#[derive(Debug, Clone)]
pub struct GoAwayConfig {
    /// Maximum streams to track for testing
    pub max_tracked_streams: u32,
    /// Whether to enable strict RFC compliance checking
    pub strict_rfc_compliance: bool,
    /// Maximum data frame size for testing
    pub max_data_frame_size: u32,
}

/// Record of processed frame after GOAWAY
#[derive(Debug, Clone)]
pub struct ProcessedFrame {
    /// Stream ID that was processed
    pub stream_id: u32,
    /// Frame type that was processed
    pub frame_type: MockFrameType,
    /// Data payload size (for DATA frames)
    pub payload_size: u32,
    /// Timestamp of processing
    pub timestamp: u64,
    /// Whether this frame should have been processed
    pub should_process: bool,
}

/// Record of discarded frame after GOAWAY
#[derive(Debug, Clone)]
pub struct DiscardedFrame {
    /// Stream ID that was discarded
    pub stream_id: u32,
    /// Frame type that was discarded
    pub frame_type: MockFrameType,
    /// Data payload size (for DATA frames)
    pub payload_size: u32,
    /// Timestamp of discard
    pub timestamp: u64,
    /// Reason for discard
    pub discard_reason: DiscardReason,
}

/// Reasons why a frame was discarded
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DiscardReason {
    /// Stream ID > last_stream_id after GOAWAY
    BeyondLastStreamId,
    /// Connection is in graceful shutdown
    GracefulShutdown,
    /// Stream is already closed/reset
    StreamClosed,
    /// Frame type not allowed after GOAWAY
    FrameTypeNotAllowed,
}

/// Violations of GOAWAY processing rules
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GoAwayViolation {
    /// DATA frame processed when it should have been discarded
    ProcessedBeyondLastStream {
        stream_id: u32,
        last_stream_id: u32,
        payload_size: u32,
    },
    /// DATA frame discarded when it should have been processed
    DiscardedWithinLastStream {
        stream_id: u32,
        last_stream_id: u32,
        payload_size: u32,
    },
    /// Multiple GOAWAY frames with non-monotonic last_stream_id
    NonMonotonicLastStreamId {
        previous_last_stream_id: u32,
        new_last_stream_id: u32,
    },
    /// New stream opened with ID > last_stream_id after GOAWAY
    NewStreamBeyondGoAway { stream_id: u32, last_stream_id: u32 },
    /// Connection closed prematurely before processing valid streams
    PrematureConnectionClose { active_streams: Vec<u32> },
}

/// Mock frame types for testing
#[derive(Debug, Clone, PartialEq, Eq, Arbitrary)]
pub enum MockFrameType {
    Data,
    Headers,
    Priority,
    RstStream,
    Settings,
    PushPromise,
    Ping,
    GoAway,
    WindowUpdate,
    Continuation,
}

/// Mock GOAWAY frame
#[derive(Debug, Clone, Arbitrary)]
pub struct MockGoAwayFrame {
    /// Last stream ID that will be processed
    pub last_stream_id: u32,
    /// Error code (usually NO_ERROR=0 for graceful shutdown)
    pub error_code: u32,
    /// Optional debug data length
    pub debug_data_length: u16,
    /// Timestamp when frame was received
    pub timestamp: u64,
}

/// Mock DATA frame
#[derive(Debug, Clone, Arbitrary)]
pub struct MockDataFrame {
    /// Stream ID for this DATA frame
    pub stream_id: u32,
    /// Payload size in bytes
    pub payload_size: u32,
    /// Whether this frame has END_STREAM flag
    pub end_stream: bool,
    /// Whether this frame has PADDED flag
    pub padded: bool,
    /// Padding length (if padded)
    pub padding_length: u8,
    /// Timestamp when frame was received
    pub timestamp: u64,
}

/// Mock stream lifecycle event
#[derive(Debug, Clone, Arbitrary)]
pub struct MockStreamEvent {
    /// Stream ID affected
    pub stream_id: u32,
    /// Type of event
    pub event_type: StreamEventType,
    /// Timestamp of event
    pub timestamp: u64,
}

/// Types of stream events
#[derive(Debug, Clone, Arbitrary)]
pub enum StreamEventType {
    /// Stream opened with HEADERS
    Open,
    /// Stream half-closed with END_STREAM
    HalfClose,
    /// Stream fully closed
    Close,
    /// Stream reset with RST_STREAM
    Reset,
}

/// Test scenario for GOAWAY + DATA interactions
#[derive(Debug, Clone, Arbitrary)]
pub struct GoAwayDataScenario {
    /// Initial stream setup events
    pub initial_streams: Vec<MockStreamEvent>,
    /// GOAWAY frame to send
    pub goaway_frame: MockGoAwayFrame,
    /// DATA frames to send after GOAWAY
    pub data_frames: Vec<MockDataFrame>,
    /// Additional GOAWAY frames (for testing multiple GOAWAYs)
    pub additional_goaways: Vec<MockGoAwayFrame>,
    /// Whether to test graceful shutdown
    pub test_graceful_shutdown: bool,
    /// Maximum operations to prevent timeouts
    pub max_operations: u16,
}

/// Results of processing a frame after GOAWAY
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FrameProcessingResult {
    /// Frame was processed normally
    Processed,
    /// Frame was discarded per GOAWAY rules
    Discarded,
    /// Frame caused a protocol violation
    ProtocolViolation,
    /// Connection should be closed due to this frame
    ConnectionClose,
}

impl Default for GoAwayConfig {
    fn default() -> Self {
        Self {
            max_tracked_streams: 1000,
            strict_rfc_compliance: true,
            max_data_frame_size: 16384, // Default max frame size
        }
    }
}

impl MockGoAwayConnection {
    pub fn new(config: GoAwayConfig) -> Self {
        Self {
            goaway_state: None,
            streams: HashMap::new(),
            processed_frames: Vec::new(),
            discarded_frames: Vec::new(),
            violations: Vec::new(),
            config,
            total_bytes_processed: 0,
            total_bytes_discarded: 0,
        }
    }

    /// Process a GOAWAY frame
    pub fn process_goaway_frame(&mut self, frame: MockGoAwayFrame) -> FrameProcessingResult {
        // Check for monotonic decrease if we already have GOAWAY
        if let Some(ref existing) = self.goaway_state {
            if frame.last_stream_id > existing.last_stream_id {
                self.violations
                    .push(GoAwayViolation::NonMonotonicLastStreamId {
                        previous_last_stream_id: existing.last_stream_id,
                        new_last_stream_id: frame.last_stream_id,
                    });
                return FrameProcessingResult::ProtocolViolation;
            }
        }

        let goaway_count = self
            .goaway_state
            .as_ref()
            .map(|state| state.goaway_count + 1)
            .unwrap_or(1);

        // Install new GOAWAY state
        self.goaway_state = Some(GoAwayState {
            last_stream_id: frame.last_stream_id,
            error_code: frame.error_code,
            received_at: frame.timestamp,
            graceful_shutdown: frame.error_code == 0, // NO_ERROR indicates graceful shutdown
            goaway_count,
        });

        // Mark streams beyond last_stream_id as discarded
        let streams_to_discard: Vec<u32> = self
            .streams
            .keys()
            .filter(|&&stream_id| stream_id > frame.last_stream_id)
            .copied()
            .collect();

        for stream_id in streams_to_discard {
            self.streams.insert(stream_id, StreamState::Discarded);
        }

        FrameProcessingResult::Processed
    }

    /// Process a DATA frame, considering GOAWAY state
    pub fn process_data_frame(&mut self, frame: MockDataFrame) -> FrameProcessingResult {
        let should_process = self.should_process_frame(frame.stream_id, MockFrameType::Data);

        if should_process {
            // Process the frame normally
            self.processed_frames.push(ProcessedFrame {
                stream_id: frame.stream_id,
                frame_type: MockFrameType::Data,
                payload_size: frame.payload_size,
                timestamp: frame.timestamp,
                should_process: true,
            });

            self.total_bytes_processed += frame.payload_size as u64;

            // Update stream state if END_STREAM
            if frame.end_stream {
                let current_state = self
                    .streams
                    .get(&frame.stream_id)
                    .cloned()
                    .unwrap_or(StreamState::Idle);
                match current_state {
                    StreamState::Open => {
                        self.streams
                            .insert(frame.stream_id, StreamState::HalfClosedRemote);
                    }
                    StreamState::HalfClosedRemote => {
                        self.streams.insert(frame.stream_id, StreamState::Closed);
                    }
                    _ => {} // No state change
                }
            }

            FrameProcessingResult::Processed
        } else {
            // Determine discard reason
            let discard_reason = if let Some(ref goaway) = self.goaway_state {
                if frame.stream_id > goaway.last_stream_id {
                    DiscardReason::BeyondLastStreamId
                } else if goaway.graceful_shutdown {
                    DiscardReason::GracefulShutdown
                } else {
                    DiscardReason::StreamClosed
                }
            } else {
                DiscardReason::StreamClosed
            };

            self.discarded_frames.push(DiscardedFrame {
                stream_id: frame.stream_id,
                frame_type: MockFrameType::Data,
                payload_size: frame.payload_size,
                timestamp: frame.timestamp,
                discard_reason,
            });

            self.total_bytes_discarded += frame.payload_size as u64;

            // Check if this should have been processed (violation)
            if let Some(ref goaway) = self.goaway_state {
                if frame.stream_id <= goaway.last_stream_id {
                    let stream_state = self
                        .streams
                        .get(&frame.stream_id)
                        .cloned()
                        .unwrap_or(StreamState::Idle);

                    // Should be processed if stream is not closed/reset
                    if !matches!(
                        stream_state,
                        StreamState::Closed | StreamState::Reset | StreamState::Discarded
                    ) {
                        self.violations
                            .push(GoAwayViolation::DiscardedWithinLastStream {
                                stream_id: frame.stream_id,
                                last_stream_id: goaway.last_stream_id,
                                payload_size: frame.payload_size,
                            });
                    }
                }
            }

            FrameProcessingResult::Discarded
        }
    }

    /// Process a stream lifecycle event
    pub fn process_stream_event(&mut self, event: MockStreamEvent) -> FrameProcessingResult {
        // Check if we should allow this stream operation after GOAWAY
        if let Some(ref goaway) = self.goaway_state {
            if event.stream_id > goaway.last_stream_id {
                match event.event_type {
                    StreamEventType::Open => {
                        self.violations
                            .push(GoAwayViolation::NewStreamBeyondGoAway {
                                stream_id: event.stream_id,
                                last_stream_id: goaway.last_stream_id,
                            });
                        return FrameProcessingResult::ProtocolViolation;
                    }
                    _ => {
                        // Other events on beyond-GOAWAY streams should be ignored
                        return FrameProcessingResult::Discarded;
                    }
                }
            }
        }

        // Update stream state
        let new_state = match event.event_type {
            StreamEventType::Open => StreamState::Open,
            StreamEventType::HalfClose => StreamState::HalfClosedRemote,
            StreamEventType::Close => StreamState::Closed,
            StreamEventType::Reset => StreamState::Reset,
        };

        self.streams.insert(event.stream_id, new_state);
        FrameProcessingResult::Processed
    }

    /// Determine if a frame should be processed given current GOAWAY state
    fn should_process_frame(&self, stream_id: u32, frame_type: MockFrameType) -> bool {
        // If no GOAWAY, process normally
        let goaway = match &self.goaway_state {
            Some(goaway) => goaway,
            None => return true,
        };

        // RFC 7540 §6.8: Frames for streams > last_stream_id must be discarded
        if stream_id > goaway.last_stream_id {
            return false;
        }

        // Check stream state
        let stream_state = self
            .streams
            .get(&stream_id)
            .cloned()
            .unwrap_or(StreamState::Idle);

        match stream_state {
            StreamState::Discarded => false,
            StreamState::Closed | StreamState::Reset => false,
            StreamState::Idle => {
                // Can only open streams <= last_stream_id
                matches!(
                    frame_type,
                    MockFrameType::Headers | MockFrameType::PushPromise
                )
            }
            StreamState::Open | StreamState::HalfClosedRemote => {
                // Can process most frame types on active streams
                true
            }
        }
    }

    /// Get all violations detected
    pub fn violations(&self) -> &[GoAwayViolation] {
        &self.violations
    }

    /// Get statistics about processing
    pub fn get_stats(&self) -> GoAwayStats {
        let active_streams = self
            .streams
            .iter()
            .filter(|(_, state)| matches!(state, StreamState::Open | StreamState::HalfClosedRemote))
            .count();

        let discarded_streams = self
            .streams
            .values()
            .filter(|state| matches!(state, StreamState::Discarded))
            .count();

        GoAwayStats {
            goaway_received: self.goaway_state.is_some(),
            last_stream_id: self.goaway_state.as_ref().map(|g| g.last_stream_id),
            active_streams,
            discarded_streams,
            frames_processed: self.processed_frames.len(),
            frames_discarded: self.discarded_frames.len(),
            total_bytes_processed: self.total_bytes_processed,
            total_bytes_discarded: self.total_bytes_discarded,
            violation_count: self.violations.len(),
        }
    }

    /// Check if connection should be closed (all streams <= last_stream_id are complete)
    pub fn should_close_connection(&self) -> bool {
        let goaway = match &self.goaway_state {
            Some(goaway) => goaway,
            None => return false,
        };

        // Connection can close when all streams <= last_stream_id are closed
        let active_valid_streams: Vec<u32> = self
            .streams
            .iter()
            .filter_map(|(&stream_id, state)| {
                if stream_id <= goaway.last_stream_id {
                    match state {
                        StreamState::Open | StreamState::HalfClosedRemote => Some(stream_id),
                        _ => None,
                    }
                } else {
                    None
                }
            })
            .collect();

        active_valid_streams.is_empty()
    }
}

/// Statistics about GOAWAY processing
#[derive(Debug, Clone)]
pub struct GoAwayStats {
    pub goaway_received: bool,
    pub last_stream_id: Option<u32>,
    pub active_streams: usize,
    pub discarded_streams: usize,
    pub frames_processed: usize,
    pub frames_discarded: usize,
    pub total_bytes_processed: u64,
    pub total_bytes_discarded: u64,
    pub violation_count: usize,
}

/// Test basic GOAWAY + DATA interaction
fn test_goaway_data_basic() {
    let mut conn = MockGoAwayConnection::new(GoAwayConfig::default());

    // Open stream 1
    conn.process_stream_event(MockStreamEvent {
        stream_id: 1,
        event_type: StreamEventType::Open,
        timestamp: 100,
    });

    // Open stream 3
    conn.process_stream_event(MockStreamEvent {
        stream_id: 3,
        event_type: StreamEventType::Open,
        timestamp: 200,
    });

    // Send GOAWAY with last_stream_id=1
    let goaway = MockGoAwayFrame {
        last_stream_id: 1,
        error_code: 0, // NO_ERROR
        debug_data_length: 0,
        timestamp: 300,
    };

    let result = conn.process_goaway_frame(goaway);
    assert_eq!(result, FrameProcessingResult::Processed);

    // DATA on stream 1 (should be processed)
    let data1 = MockDataFrame {
        stream_id: 1,
        payload_size: 100,
        end_stream: false,
        padded: false,
        padding_length: 0,
        timestamp: 400,
    };

    let result = conn.process_data_frame(data1);
    assert_eq!(result, FrameProcessingResult::Processed);

    // DATA on stream 3 (should be discarded)
    let data3 = MockDataFrame {
        stream_id: 3,
        payload_size: 200,
        end_stream: false,
        padded: false,
        padding_length: 0,
        timestamp: 500,
    };

    let result = conn.process_data_frame(data3);
    assert_eq!(result, FrameProcessingResult::Discarded);

    // Verify statistics
    let stats = conn.get_stats();
    assert_eq!(stats.total_bytes_processed, 100);
    assert_eq!(stats.total_bytes_discarded, 200);
    assert_eq!(stats.frames_processed, 1);
    assert_eq!(stats.frames_discarded, 1);

    // Check stream states
    assert_eq!(conn.streams[&1], StreamState::Open);
    assert_eq!(conn.streams[&3], StreamState::Discarded);
}

/// Test multiple GOAWAY frames with monotonic decrease
fn test_multiple_goaway_frames() {
    let mut conn = MockGoAwayConnection::new(GoAwayConfig::default());

    // First GOAWAY with last_stream_id=10
    let goaway1 = MockGoAwayFrame {
        last_stream_id: 10,
        error_code: 0,
        debug_data_length: 0,
        timestamp: 100,
    };
    conn.process_goaway_frame(goaway1);

    // Second GOAWAY with last_stream_id=5 (valid decrease)
    let goaway2 = MockGoAwayFrame {
        last_stream_id: 5,
        error_code: 0,
        debug_data_length: 0,
        timestamp: 200,
    };
    let result = conn.process_goaway_frame(goaway2);
    assert_eq!(result, FrameProcessingResult::Processed);

    // Third GOAWAY with last_stream_id=7 (invalid increase)
    let goaway3 = MockGoAwayFrame {
        last_stream_id: 7,
        error_code: 0,
        debug_data_length: 0,
        timestamp: 300,
    };
    let result = conn.process_goaway_frame(goaway3);
    assert_eq!(result, FrameProcessingResult::ProtocolViolation);

    // Check violations
    let violations = conn.violations();
    assert_eq!(violations.len(), 1);
    assert!(matches!(
        violations[0],
        GoAwayViolation::NonMonotonicLastStreamId { .. }
    ));
}

/// Test new stream creation after GOAWAY
fn test_new_stream_after_goaway() {
    let mut conn = MockGoAwayConnection::new(GoAwayConfig::default());

    // Send GOAWAY with last_stream_id=5
    let goaway = MockGoAwayFrame {
        last_stream_id: 5,
        error_code: 0,
        debug_data_length: 0,
        timestamp: 100,
    };
    conn.process_goaway_frame(goaway);

    // Try to open stream 7 (should be violation)
    let stream_event = MockStreamEvent {
        stream_id: 7,
        event_type: StreamEventType::Open,
        timestamp: 200,
    };

    let result = conn.process_stream_event(stream_event);
    assert_eq!(result, FrameProcessingResult::ProtocolViolation);

    // Check violations
    let violations = conn.violations();
    assert_eq!(violations.len(), 1);
    assert!(matches!(
        violations[0],
        GoAwayViolation::NewStreamBeyondGoAway { .. }
    ));
}

/// Test graceful connection close timing
fn test_connection_close_timing() {
    let mut conn = MockGoAwayConnection::new(GoAwayConfig::default());

    // Open streams 1 and 3
    conn.process_stream_event(MockStreamEvent {
        stream_id: 1,
        event_type: StreamEventType::Open,
        timestamp: 100,
    });
    conn.process_stream_event(MockStreamEvent {
        stream_id: 3,
        event_type: StreamEventType::Open,
        timestamp: 200,
    });

    // GOAWAY with last_stream_id=1
    let goaway = MockGoAwayFrame {
        last_stream_id: 1,
        error_code: 0,
        debug_data_length: 0,
        timestamp: 300,
    };
    conn.process_goaway_frame(goaway);

    // Connection should not close yet (stream 1 still open)
    assert!(!conn.should_close_connection());

    // Close stream 1
    conn.process_stream_event(MockStreamEvent {
        stream_id: 1,
        event_type: StreamEventType::Close,
        timestamp: 400,
    });

    // Now connection should be ready to close
    assert!(conn.should_close_connection());
}

fuzz_target!(|scenario: GoAwayDataScenario| {
    // Limit operations to prevent timeouts
    let max_ops = scenario.max_operations.min(500);
    let limited_streams: Vec<MockStreamEvent> = scenario
        .initial_streams
        .into_iter()
        .take(max_ops as usize / 4)
        .collect();
    let limited_data_frames: Vec<MockDataFrame> = scenario
        .data_frames
        .into_iter()
        .take(max_ops as usize / 2)
        .collect();
    let limited_additional_goaways: Vec<MockGoAwayFrame> = scenario
        .additional_goaways
        .into_iter()
        .take(5) // Limit GOAWAY frames
        .collect();

    let mut config = GoAwayConfig::default();
    config.max_tracked_streams = 100; // Smaller limit for fuzzing

    let mut conn = MockGoAwayConnection::new(config);

    // Set up initial streams
    for stream_event in &limited_streams {
        conn.process_stream_event(stream_event.clone());
    }

    // Process the main GOAWAY frame
    let goaway_result = conn.process_goaway_frame(scenario.goaway_frame.clone());

    // Verify GOAWAY was processed (unless it was a protocol violation)
    match goaway_result {
        FrameProcessingResult::Processed => {
            assert!(
                conn.goaway_state.is_some(),
                "GOAWAY state should be set after processing"
            );
        }
        FrameProcessingResult::ProtocolViolation => {
            // Expected for invalid GOAWAY frames
        }
        _ => {
            panic!("Unexpected GOAWAY processing result: {:?}", goaway_result);
        }
    }

    // Process DATA frames after GOAWAY
    let mut processed_count = 0;
    let mut discarded_count = 0;

    for data_frame in &limited_data_frames {
        let result = conn.process_data_frame(data_frame.clone());
        match result {
            FrameProcessingResult::Processed => processed_count += 1,
            FrameProcessingResult::Discarded => discarded_count += 1,
            _ => {} // Protocol violations are tracked separately
        }
    }

    // Process additional GOAWAY frames
    for additional_goaway in &limited_additional_goaways {
        conn.process_goaway_frame(additional_goaway.clone());
    }

    // Verify frame processing logic
    let stats = conn.get_stats();
    assert_eq!(stats.frames_processed, processed_count);
    assert_eq!(stats.frames_discarded, discarded_count);

    // Verify no DATA frames were processed beyond last_stream_id
    if let Some(ref goaway) = conn.goaway_state {
        for processed in &conn.processed_frames {
            if processed.frame_type == MockFrameType::Data {
                assert!(
                    processed.stream_id <= goaway.last_stream_id,
                    "DATA frame on stream {} processed after GOAWAY last_stream_id={}",
                    processed.stream_id,
                    goaway.last_stream_id
                );
            }
        }

        // Verify discarded frames were actually beyond last_stream_id or on closed streams
        for discarded in &conn.discarded_frames {
            if discarded.frame_type == MockFrameType::Data {
                if discarded.discard_reason == DiscardReason::BeyondLastStreamId {
                    assert!(
                        discarded.stream_id > goaway.last_stream_id,
                        "DATA frame on stream {} discarded with BeyondLastStreamId but <= last_stream_id={}",
                        discarded.stream_id,
                        goaway.last_stream_id
                    );
                }
            }
        }
    }

    // Verify total byte accounting
    let expected_total = conn.total_bytes_processed + conn.total_bytes_discarded;
    let actual_total: u64 = limited_data_frames
        .iter()
        .map(|f| f.payload_size as u64)
        .sum();
    assert_eq!(
        expected_total, actual_total,
        "Byte accounting mismatch: processed={} + discarded={} != total={}",
        conn.total_bytes_processed, conn.total_bytes_discarded, actual_total
    );

    // Run specific edge case tests periodically
    if limited_data_frames.len() == 1 {
        test_goaway_data_basic();
        test_multiple_goaway_frames();
        test_new_stream_after_goaway();
        test_connection_close_timing();
    }

    // Verify no protocol violations for basic cases
    if scenario.goaway_frame.error_code == 0 && limited_additional_goaways.is_empty() {
        let critical_violations: Vec<_> = conn
            .violations()
            .iter()
            .filter(|v| {
                matches!(
                    v,
                    GoAwayViolation::ProcessedBeyondLastStream { .. }
                        | GoAwayViolation::NonMonotonicLastStreamId { .. }
                )
            })
            .collect();
        assert!(
            critical_violations.is_empty(),
            "Critical GOAWAY protocol violations found: {:?}",
            critical_violations
        );
    }
});
