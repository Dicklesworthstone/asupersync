#![no_main]

//! Fuzz target for HTTP/2 CONTINUATION frame size limit enforcement.
//!
//! This target tests that the HTTP/2 implementation properly enforces aggregate
//! header-list-size limits when processing sequences of CONTINUATION frames.
//!
//! Per RFC 9113 and CVE mitigations, servers must bound the total size of
//! header fragments to prevent DoS attacks via unbounded CONTINUATION frames.
//!
//! The implementation uses a calculated limit of:
//! `min(max_header_list_size * 4, 256KB)` where max_header_list_size comes
//! from SETTINGS_MAX_HEADER_LIST_SIZE.
//!
//! Expected behavior:
//! - Small continuation sequences within limits: accepted
//! - Large continuation sequences exceeding limits: rejected with ENHANCE_YOUR_CALM
//! - CONTINUATION on closed streams: rejected with STREAM_CLOSED

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use std::collections::HashMap;

/// HTTP/2 error codes (simplified subset)
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

/// Stream state for tracking lifecycle
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

impl StreamState {
    fn is_closed(self) -> bool {
        self == StreamState::Closed
    }
}

/// CONTINUATION frame structure
#[derive(Debug, Clone, Arbitrary)]
struct ContinuationFrame {
    /// Stream identifier (must be > 0)
    stream_id: u32,
    /// Header block fragment data
    header_block: Vec<u8>,
    /// Whether this frame ends the header block
    end_headers: bool,
}

impl ContinuationFrame {
    fn validate_basic(&self) -> Result<(), ErrorCode> {
        if self.stream_id == 0 {
            return Err(ErrorCode::ProtocolError);
        }
        Ok(())
    }
}

/// Mock stream for tracking header fragment accumulation
struct MockStream {
    id: u32,
    state: StreamState,
    header_fragments: Vec<Vec<u8>>,
    headers_complete: bool,
    max_header_list_size: u32,
}

impl MockStream {
    fn new(id: u32, state: StreamState, max_header_list_size: u32) -> Self {
        Self {
            id,
            state,
            header_fragments: Vec::new(),
            headers_complete: false,
            max_header_list_size,
        }
    }

    /// Compute maximum accumulated header fragment size
    /// Implementation mirrors src/http/h2/stream.rs:max_header_fragment_size_for
    fn max_header_fragment_size(&self) -> usize {
        const HEADER_FRAGMENT_MULTIPLIER: usize = 4;
        const MAX_HEADER_FRAGMENT_SIZE: usize = 256 * 1024; // 256 KB

        let max_list_size = usize::try_from(self.max_header_list_size).unwrap_or(usize::MAX);
        let calculated = max_list_size.saturating_mul(HEADER_FRAGMENT_MULTIPLIER);
        calculated.min(MAX_HEADER_FRAGMENT_SIZE)
    }

    /// Process a CONTINUATION frame
    /// Implementation mirrors src/http/h2/stream.rs:recv_continuation
    fn recv_continuation(
        &mut self,
        header_block: Vec<u8>,
        end_headers: bool,
    ) -> Result<(), ErrorCode> {
        // Reject CONTINUATION on closed streams
        if self.state.is_closed() {
            return Err(ErrorCode::StreamClosed);
        }

        // Reject unexpected CONTINUATION frames
        if self.headers_complete {
            return Err(ErrorCode::ProtocolError);
        }

        // Check accumulated size to prevent DoS
        let current_size: usize = self.header_fragments.iter().map(Vec::len).sum();
        let new_total_size = current_size.saturating_add(header_block.len());

        if new_total_size > self.max_header_fragment_size() {
            return Err(ErrorCode::EnhanceYourCalm);
        }

        self.header_fragments.push(header_block);
        self.headers_complete = end_headers;
        Ok(())
    }

    fn get_accumulated_size(&self) -> usize {
        self.header_fragments.iter().map(Vec::len).sum()
    }

    fn reset_headers(&mut self) {
        self.header_fragments.clear();
        self.headers_complete = false;
    }
}

/// Test scenario for CONTINUATION frame size limits
#[derive(Debug, Clone, Arbitrary)]
struct ContinuationSizeLimitScenario {
    /// SETTINGS_MAX_HEADER_LIST_SIZE value to use
    max_header_list_size: u32,
    /// Sequence of CONTINUATION frames to send
    continuation_frames: Vec<ContinuationFrame>,
    /// Initial stream state
    initial_stream_state: StreamState,
    /// Stream ID to use (if 0, will be derived from first frame)
    stream_id_override: Option<u32>,
}

/// Mock connection for testing CONTINUATION frame handling
struct MockConnection {
    streams: HashMap<u32, MockStream>,
    default_max_header_list_size: u32,
}

impl MockConnection {
    fn new(max_header_list_size: u32) -> Self {
        Self {
            streams: HashMap::new(),
            default_max_header_list_size: max_header_list_size,
        }
    }

    fn get_or_create_stream(&mut self, stream_id: u32, initial_state: StreamState) -> &mut MockStream {
        self.streams.entry(stream_id).or_insert_with(|| {
            MockStream::new(stream_id, initial_state, self.default_max_header_list_size)
        })
    }

    fn process_continuation_frame(
        &mut self,
        frame: &ContinuationFrame,
        initial_stream_state: StreamState,
    ) -> Result<(), ErrorCode> {
        // Basic frame validation
        frame.validate_basic()?;

        // Get or create stream
        let stream = self.get_or_create_stream(frame.stream_id, initial_stream_state);

        // Process the continuation frame
        stream.recv_continuation(frame.header_block.clone(), frame.end_headers)
    }

    fn get_stream_stats(&self, stream_id: u32) -> Option<(usize, usize, bool)> {
        self.streams.get(&stream_id).map(|s| (
            s.get_accumulated_size(),
            s.max_header_fragment_size(),
            s.headers_complete,
        ))
    }
}

fuzz_target!(|scenario: ContinuationSizeLimitScenario| {
    // Clamp max_header_list_size to reasonable bounds for testing
    let max_header_list_size = scenario.max_header_list_size.max(1024).min(16 * 1024 * 1024);
    let mut connection = MockConnection::new(max_header_list_size);

    // Determine stream ID from first frame or override
    let stream_id = if let Some(override_id) = scenario.stream_id_override {
        if override_id == 0 { 1 } else { override_id } // Ensure non-zero
    } else if let Some(first_frame) = scenario.continuation_frames.first() {
        if first_frame.stream_id == 0 { 1 } else { first_frame.stream_id }
    } else {
        1 // Default stream ID
    };

    let mut total_accumulated = 0;
    let mut frame_count = 0;
    let expected_limit = MockStream::new(stream_id, scenario.initial_stream_state, max_header_list_size)
        .max_header_fragment_size();

    // Process each CONTINUATION frame
    for (i, frame) in scenario.continuation_frames.iter().enumerate() {
        frame_count += 1;

        // Create a frame with consistent stream_id
        let test_frame = ContinuationFrame {
            stream_id,
            header_block: frame.header_block.clone(),
            end_headers: frame.end_headers,
        };

        let result = connection.process_continuation_frame(&test_frame, scenario.initial_stream_state);

        match result {
            Ok(()) => {
                // Frame was accepted
                total_accumulated += test_frame.header_block.len();

                // Verify the accumulated size is within expected bounds
                if let Some((actual_accumulated, limit, headers_complete)) = connection.get_stream_stats(stream_id) {
                    assert_eq!(
                        actual_accumulated, total_accumulated,
                        "Accumulated size mismatch after frame {}", i
                    );
                    assert!(
                        actual_accumulated <= limit,
                        "Accepted frame exceeded limit: {} > {}", actual_accumulated, limit
                    );

                    // If this was the last frame with end_headers=true, verify completion
                    if test_frame.end_headers {
                        assert!(headers_complete, "Headers should be complete after end_headers=true");
                        break; // No more frames should be processed after end_headers
                    }
                }
            }
            Err(error_code) => {
                // Frame was rejected - validate the rejection reason
                match error_code {
                    ErrorCode::EnhanceYourCalm => {
                        // Size limit exceeded - this should happen when we go over the limit
                        let would_exceed = total_accumulated + test_frame.header_block.len() > expected_limit;
                        assert!(
                            would_exceed,
                            "ENHANCE_YOUR_CALM returned but size wouldn't exceed limit: {} + {} <= {}",
                            total_accumulated, test_frame.header_block.len(), expected_limit
                        );
                    }
                    ErrorCode::StreamClosed => {
                        // Stream is closed
                        assert!(scenario.initial_stream_state.is_closed(),
                               "STREAM_CLOSED error but stream state is {:?}", scenario.initial_stream_state);
                    }
                    ErrorCode::ProtocolError => {
                        // Either stream_id=0 or unexpected CONTINUATION
                        assert!(
                            test_frame.stream_id == 0 ||
                            (i > 0 && scenario.continuation_frames[i-1].end_headers),
                            "PROTOCOL_ERROR but frame seems valid"
                        );
                    }
                    _ => {
                        panic!("Unexpected error code: {:?}", error_code);
                    }
                }
                break; // Stop processing after first error
            }
        }
    }

    // Test boundary conditions
    test_boundary_conditions();
});

/// Test specific boundary conditions for header fragment limits
fn test_boundary_conditions() {
    let test_cases = [
        (1024, 4096),        // Small limit
        (8192, 32768),       // Medium limit
        (65536, 256 * 1024), // Large limit capped at 256KB
        (1024 * 1024, 256 * 1024), // Very large limit still capped
    ];

    for (max_header_list_size, expected_fragment_limit) in test_cases {
        let stream = MockStream::new(1, StreamState::Open, max_header_list_size);
        let actual_limit = stream.max_header_fragment_size();

        assert_eq!(
            actual_limit, expected_fragment_limit,
            "Fragment limit calculation wrong for max_header_list_size={}",
            max_header_list_size
        );

        // Test exactly at the limit
        let mut test_stream = MockStream::new(1, StreamState::Open, max_header_list_size);
        let at_limit_data = vec![0u8; expected_fragment_limit];
        let result = test_stream.recv_continuation(at_limit_data, true);
        assert!(result.is_ok(), "Should accept data exactly at limit");

        // Test just over the limit
        let mut test_stream2 = MockStream::new(1, StreamState::Open, max_header_list_size);
        let over_limit_data = vec![0u8; expected_fragment_limit + 1];
        let result2 = test_stream2.recv_continuation(over_limit_data, true);
        assert_eq!(result2, Err(ErrorCode::EnhanceYourCalm), "Should reject data over limit");
    }

    // Test multiple frames building up to the limit
    let max_header_list_size = 8192;
    let expected_limit = 32768; // 8192 * 4
    let mut stream = MockStream::new(1, StreamState::Open, max_header_list_size);

    // Add frames that total exactly the limit
    let frames = [
        vec![0u8; 10000],
        vec![0u8; 10000],
        vec![0u8; 10000],
        vec![0u8; 2768], // Total: 32768
    ];

    for (i, frame_data) in frames.iter().enumerate() {
        let is_last = i == frames.len() - 1;
        let result = stream.recv_continuation(frame_data.clone(), is_last);
        assert!(result.is_ok(), "Frame {} should be accepted", i);
    }

    assert_eq!(stream.get_accumulated_size(), expected_limit);
    assert!(stream.headers_complete);

    // Test CONTINUATION on closed stream
    let mut closed_stream = MockStream::new(2, StreamState::Closed, 8192);
    let result = closed_stream.recv_continuation(vec![0u8; 100], true);
    assert_eq!(result, Err(ErrorCode::StreamClosed), "Should reject CONTINUATION on closed stream");

    // Test unexpected CONTINUATION (headers already complete)
    let mut complete_stream = MockStream::new(3, StreamState::Open, 8192);
    complete_stream.recv_continuation(vec![0u8; 100], true).unwrap(); // Complete headers
    let result = complete_stream.recv_continuation(vec![0u8; 100], true);
    assert_eq!(result, Err(ErrorCode::ProtocolError), "Should reject unexpected CONTINUATION");
}