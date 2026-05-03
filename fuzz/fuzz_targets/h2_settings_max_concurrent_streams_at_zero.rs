#![no_main]

//! Fuzz target: HTTP/2 SETTINGS_MAX_CONCURRENT_STREAMS=0 flow control
//!
//! Tests the scenario where a peer sends SETTINGS_MAX_CONCURRENT_STREAMS=0,
//! which should block ALL new stream creation until the limit is increased.
//! This is a critical flow control mechanism per RFC 7540 §6.5.2.
//!
//! Key behaviors tested:
//! - Stream creation blocks when limit is 0
//! - Blocked stream creation succeeds when limit increases
//! - Stream lifecycle tracking respects the limit
//! - Proper handling of stream close/limit interactions

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

/// HTTP/2 frame type identifiers
const SETTINGS_TYPE: u8 = 0x4;
const HEADERS_TYPE: u8 = 0x1;
const DATA_TYPE: u8 = 0x0;

/// HTTP/2 SETTINGS parameter identifiers (RFC 7540 §6.5.2)
const SETTINGS_HEADER_TABLE_SIZE: u16 = 0x1;
const SETTINGS_ENABLE_PUSH: u16 = 0x2;
const SETTINGS_MAX_CONCURRENT_STREAMS: u16 = 0x3;
const SETTINGS_INITIAL_WINDOW_SIZE: u16 = 0x4;
const SETTINGS_MAX_FRAME_SIZE: u16 = 0x5;
const SETTINGS_MAX_HEADER_LIST_SIZE: u16 = 0x6;

/// HTTP/2 frame flags
const SETTINGS_ACK_FLAG: u8 = 0x1;
const HEADERS_END_HEADERS_FLAG: u8 = 0x4;
const HEADERS_END_STREAM_FLAG: u8 = 0x1;

/// Stream states for tracking
#[derive(Debug, Clone, PartialEq)]
enum StreamState {
    Idle,
    Open,
    Closed,
}

/// Stream tracking entry
#[derive(Debug, Clone)]
struct StreamEntry {
    stream_id: u32,
    state: StreamState,
}

/// Mock parser for HTTP/2 SETTINGS frame with MAX_CONCURRENT_STREAMS validation
#[derive(Debug)]
struct MockH2MaxConcurrentStreamsParser {
    max_concurrent_streams: Option<u32>, // None = unlimited (default)
    active_streams: Vec<StreamEntry>,
    next_stream_id: u32,
}

/// Result types for operations
#[derive(Debug, PartialEq)]
enum ParseResult {
    /// Settings frame processed successfully
    SettingsProcessed(u32), // new limit (0 = blocked)
    /// Stream creation attempt
    StreamCreationAttempt(StreamCreationResult),
    /// Frame processed (other frame types)
    FrameProcessed,
    /// Protocol error
    ProtocolError(String),
}

#[derive(Debug, PartialEq)]
enum StreamCreationResult {
    /// Stream created successfully
    Success(u32), // stream_id
    /// Stream creation blocked due to limit
    Blocked(String),
    /// Error (invalid stream id, etc.)
    Error(String),
}

/// Input for fuzz testing
#[derive(Debug, Arbitrary)]
struct H2MaxConcurrentStreamsInput {
    /// Initial settings to establish baseline
    initial_limit: Option<u32>, // None = unlimited, Some(n) = specific limit

    /// Sequence of operations to test
    operations: Vec<Operation>,

    /// Frame size limit for testing (16384..65535)
    #[arbitrary(with = |u: &mut arbitrary::Unstructured| u.int_in_range(16384..=65535))]
    max_frame_size: u32,
}

#[derive(Debug, Arbitrary)]
enum Operation {
    /// Send SETTINGS frame with new MAX_CONCURRENT_STREAMS
    UpdateLimit(Option<u32>), // None = remove limit, Some(n) = set limit

    /// Attempt to create a new stream
    CreateStream,

    /// Close an existing stream
    CloseStream(u32), // stream_id (0 = close oldest)

    /// Send other frame types (should not affect limit)
    SendHeadersFrame(u32, bool), // stream_id, end_stream
    SendDataFrame(u32, bool), // stream_id, end_stream
}

impl MockH2MaxConcurrentStreamsParser {
    fn new() -> Self {
        Self {
            max_concurrent_streams: None, // RFC default: unlimited
            active_streams: Vec::new(),
            next_stream_id: 1, // Client streams are odd-numbered
        }
    }

    /// Process SETTINGS frame
    fn process_settings(&mut self, settings: &[(u16, u32)]) -> Result<ParseResult, String> {
        for &(setting_id, value) in settings {
            match setting_id {
                SETTINGS_MAX_CONCURRENT_STREAMS => {
                    // RFC 7540 §6.5.2: Value of 0 means no new streams allowed
                    self.max_concurrent_streams = if value == 0 { Some(0) } else { Some(value) };
                    return Ok(ParseResult::SettingsProcessed(value));
                }
                SETTINGS_HEADER_TABLE_SIZE
                | SETTINGS_ENABLE_PUSH
                | SETTINGS_INITIAL_WINDOW_SIZE
                | SETTINGS_MAX_FRAME_SIZE
                | SETTINGS_MAX_HEADER_LIST_SIZE => {
                    // Other settings - ignore for this test
                }
                _ => {
                    // Unknown setting - ignore per RFC 7540 §6.5
                }
            }
        }
        Ok(ParseResult::FrameProcessed)
    }

    /// Attempt to create a new outbound stream
    fn attempt_create_stream(&mut self) -> ParseResult {
        let stream_id = self.next_stream_id;

        // Check concurrent streams limit
        if let Some(limit) = self.max_concurrent_streams {
            let active_count = self.count_active_streams();
            if active_count >= limit {
                return ParseResult::StreamCreationAttempt(StreamCreationResult::Blocked(format!(
                    "Stream creation blocked: {}/{} streams active",
                    active_count, limit
                )));
            }
        }

        // Create the stream
        self.active_streams.push(StreamEntry {
            stream_id,
            state: StreamState::Open,
        });

        self.next_stream_id += 2; // Client streams are odd-numbered

        ParseResult::StreamCreationAttempt(StreamCreationResult::Success(stream_id))
    }

    /// Close a stream
    fn close_stream(&mut self, stream_id: u32) -> ParseResult {
        if stream_id == 0 {
            // Close the oldest active stream
            if let Some(pos) = self
                .active_streams
                .iter()
                .position(|s| s.state == StreamState::Open)
            {
                self.active_streams[pos].state = StreamState::Closed;
            }
        } else {
            // Close specific stream
            if let Some(stream) = self
                .active_streams
                .iter_mut()
                .find(|s| s.stream_id == stream_id)
            {
                stream.state = StreamState::Closed;
            }
        }
        ParseResult::FrameProcessed
    }

    /// Count currently active (open) streams
    fn count_active_streams(&self) -> u32 {
        self.active_streams
            .iter()
            .filter(|s| s.state == StreamState::Open)
            .count() as u32
    }

    /// Process various frame types (for completeness)
    fn process_headers_frame(&mut self, stream_id: u32, end_stream: bool) -> ParseResult {
        // Find or create stream entry
        if let Some(stream) = self
            .active_streams
            .iter_mut()
            .find(|s| s.stream_id == stream_id)
        {
            if end_stream {
                stream.state = StreamState::Closed;
            }
        } else if stream_id % 2 == 0 {
            // Peer-initiated stream
            self.active_streams.push(StreamEntry {
                stream_id,
                state: if end_stream {
                    StreamState::Closed
                } else {
                    StreamState::Open
                },
            });
        }
        ParseResult::FrameProcessed
    }

    fn process_data_frame(&mut self, stream_id: u32, end_stream: bool) -> ParseResult {
        if let Some(stream) = self
            .active_streams
            .iter_mut()
            .find(|s| s.stream_id == stream_id)
        {
            if end_stream {
                stream.state = StreamState::Closed;
            }
        }
        ParseResult::FrameProcessed
    }
}

/// Encode SETTINGS frame with MAX_CONCURRENT_STREAMS
fn encode_settings_frame(settings: &[(u16, u32)], max_frame_size: u32) -> Vec<u8> {
    let payload_len = settings.len() * 6; // Each setting is 6 bytes

    if payload_len > max_frame_size as usize {
        // Frame too large - truncate
        let max_settings = max_frame_size as usize / 6;
        let truncated: Vec<_> = settings.iter().take(max_settings).cloned().collect();
        return encode_settings_frame(&truncated, max_frame_size);
    }

    let mut frame = Vec::new();

    // Frame header (9 bytes)
    frame.extend_from_slice(&(payload_len as u32).to_be_bytes()[1..4]); // Length (24 bits)
    frame.push(SETTINGS_TYPE); // Type
    frame.push(0); // Flags (no ACK)
    frame.extend_from_slice(&0u32.to_be_bytes()); // Stream ID (0 for SETTINGS)

    // Settings payload
    for &(setting_id, value) in settings {
        frame.extend_from_slice(&setting_id.to_be_bytes());
        frame.extend_from_slice(&value.to_be_bytes());
    }

    frame
}

/// Process the input through our mock parser
fn process_input(input: &H2MaxConcurrentStreamsInput) -> Vec<ParseResult> {
    let mut parser = MockH2MaxConcurrentStreamsParser::new();
    let mut results = Vec::new();

    // Set initial limit if specified
    if let Some(limit) = input.initial_limit {
        let settings = vec![(SETTINGS_MAX_CONCURRENT_STREAMS, limit)];
        match parser.process_settings(&settings) {
            Ok(result) => results.push(result),
            Err(e) => results.push(ParseResult::ProtocolError(e)),
        }
    }

    // Process operations sequence
    for operation in &input.operations {
        let result = match operation {
            Operation::UpdateLimit(limit_opt) => {
                let limit = limit_opt.unwrap_or(u32::MAX); // None = unlimited
                let settings = vec![(SETTINGS_MAX_CONCURRENT_STREAMS, limit)];
                match parser.process_settings(&settings) {
                    Ok(result) => result,
                    Err(e) => ParseResult::ProtocolError(e),
                }
            }
            Operation::CreateStream => parser.attempt_create_stream(),
            Operation::CloseStream(stream_id) => parser.close_stream(*stream_id),
            Operation::SendHeadersFrame(stream_id, end_stream) => {
                parser.process_headers_frame(*stream_id, *end_stream)
            }
            Operation::SendDataFrame(stream_id, end_stream) => {
                parser.process_data_frame(*stream_id, *end_stream)
            }
        };
        results.push(result);
    }

    results
}

fuzz_target!(|input: H2MaxConcurrentStreamsInput| {
    // Skip degenerate inputs
    if input.operations.is_empty() {
        return;
    }

    let results = process_input(&input);

    // Test key invariants
    for (i, result) in results.iter().enumerate() {
        match result {
            ParseResult::SettingsProcessed(0) => {
                // When limit is set to 0, subsequent stream creation should be blocked
                for subsequent_result in results.iter().skip(i + 1) {
                    if let ParseResult::StreamCreationAttempt(StreamCreationResult::Success(_)) =
                        subsequent_result
                    {
                        // Check if there was an intervening limit increase
                        let has_increase = results.iter()
                            .skip(i + 1)
                            .take_while(|r| !matches!(r, ParseResult::StreamCreationAttempt(_)))
                            .any(|r| matches!(r, ParseResult::SettingsProcessed(limit) if *limit > 0));

                        if !has_increase {
                            panic!("Stream creation succeeded despite MAX_CONCURRENT_STREAMS=0");
                        }
                    }
                }
            }
            ParseResult::StreamCreationAttempt(StreamCreationResult::Blocked(_)) => {
                // Blocked creation is expected when limit is 0 or exceeded
            }
            ParseResult::StreamCreationAttempt(StreamCreationResult::Success(_)) => {
                // Success is valid when within limits
            }
            ParseResult::FrameProcessed => {
                // Regular frame processing
            }
            ParseResult::ProtocolError(_) => {
                // Protocol errors are acceptable for malformed inputs
            }
        }
    }
});

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_unlimited_by_default() {
        let mut parser = MockH2MaxConcurrentStreamsParser::new();

        // Should be able to create streams without limit
        for _ in 0..100 {
            match parser.attempt_create_stream() {
                ParseResult::StreamCreationAttempt(StreamCreationResult::Success(_)) => {}
                other => panic!("Expected success, got {:?}", other),
            }
        }
    }

    #[test]
    fn test_zero_limit_blocks_creation() {
        let mut parser = MockH2MaxConcurrentStreamsParser::new();

        // Set limit to 0
        let settings = vec![(SETTINGS_MAX_CONCURRENT_STREAMS, 0)];
        parser.process_settings(&settings).unwrap();

        // Stream creation should be blocked
        match parser.attempt_create_stream() {
            ParseResult::StreamCreationAttempt(StreamCreationResult::Blocked(_)) => {}
            other => panic!("Expected blocked, got {:?}", other),
        }
    }

    #[test]
    fn test_limit_enforcement() {
        let mut parser = MockH2MaxConcurrentStreamsParser::new();

        // Set limit to 2
        let settings = vec![(SETTINGS_MAX_CONCURRENT_STREAMS, 2)];
        parser.process_settings(&settings).unwrap();

        // Create 2 streams (should succeed)
        for i in 0..2 {
            match parser.attempt_create_stream() {
                ParseResult::StreamCreationAttempt(StreamCreationResult::Success(_)) => {}
                other => panic!("Stream {} creation failed: {:?}", i, other),
            }
        }

        // Third stream should be blocked
        match parser.attempt_create_stream() {
            ParseResult::StreamCreationAttempt(StreamCreationResult::Blocked(_)) => {}
            other => panic!("Expected blocked, got {:?}", other),
        }
    }

    #[test]
    fn test_stream_close_allows_new_creation() {
        let mut parser = MockH2MaxConcurrentStreamsParser::new();

        // Set limit to 1
        let settings = vec![(SETTINGS_MAX_CONCURRENT_STREAMS, 1)];
        parser.process_settings(&settings).unwrap();

        // Create 1 stream
        let stream_id = match parser.attempt_create_stream() {
            ParseResult::StreamCreationAttempt(StreamCreationResult::Success(id)) => id,
            other => panic!("Expected success, got {:?}", other),
        };

        // Second stream should be blocked
        match parser.attempt_create_stream() {
            ParseResult::StreamCreationAttempt(StreamCreationResult::Blocked(_)) => {}
            other => panic!("Expected blocked, got {:?}", other),
        }

        // Close the first stream
        parser.close_stream(stream_id);

        // Now should be able to create a new stream
        match parser.attempt_create_stream() {
            ParseResult::StreamCreationAttempt(StreamCreationResult::Success(_)) => {}
            other => panic!("Expected success after close, got {:?}", other),
        }
    }

    #[test]
    fn test_limit_increase_allows_creation() {
        let mut parser = MockH2MaxConcurrentStreamsParser::new();

        // Set limit to 0 (block all)
        let settings = vec![(SETTINGS_MAX_CONCURRENT_STREAMS, 0)];
        parser.process_settings(&settings).unwrap();

        // Stream creation should be blocked
        match parser.attempt_create_stream() {
            ParseResult::StreamCreationAttempt(StreamCreationResult::Blocked(_)) => {}
            other => panic!("Expected blocked, got {:?}", other),
        }

        // Increase limit to 1
        let settings = vec![(SETTINGS_MAX_CONCURRENT_STREAMS, 1)];
        parser.process_settings(&settings).unwrap();

        // Now should be able to create a stream
        match parser.attempt_create_stream() {
            ParseResult::StreamCreationAttempt(StreamCreationResult::Success(_)) => {}
            other => panic!("Expected success after limit increase, got {:?}", other),
        }
    }

    #[test]
    fn test_settings_frame_encoding() {
        let settings = vec![(SETTINGS_MAX_CONCURRENT_STREAMS, 0)];
        let frame = encode_settings_frame(&settings, 16384);

        // Check frame structure
        assert_eq!(frame.len(), 9 + 6); // Header + one setting
        assert_eq!(frame[3], SETTINGS_TYPE); // Frame type
        assert_eq!(frame[4], 0); // No flags

        // Check setting payload
        let setting_id = u16::from_be_bytes([frame[9], frame[10]]);
        let setting_value = u32::from_be_bytes([frame[11], frame[12], frame[13], frame[14]]);
        assert_eq!(setting_id, SETTINGS_MAX_CONCURRENT_STREAMS);
        assert_eq!(setting_value, 0);
    }

    #[test]
    fn test_boundary_limit_values() {
        let mut parser = MockH2MaxConcurrentStreamsParser::new();

        // Test with u32::MAX (effectively unlimited)
        let settings = vec![(SETTINGS_MAX_CONCURRENT_STREAMS, u32::MAX)];
        match parser.process_settings(&settings) {
            Ok(ParseResult::SettingsProcessed(u32::MAX)) => {}
            other => panic!("Expected settings processed, got {:?}", other),
        }

        // Should be able to create many streams
        for _ in 0..10 {
            match parser.attempt_create_stream() {
                ParseResult::StreamCreationAttempt(StreamCreationResult::Success(_)) => {}
                other => panic!("Expected success with max limit, got {:?}", other),
            }
        }
    }

    #[test]
    fn test_mixed_operations() {
        let input = H2MaxConcurrentStreamsInput {
            initial_limit: Some(2),
            operations: vec![
                Operation::CreateStream,
                Operation::CreateStream,
                Operation::CreateStream,         // This should be blocked
                Operation::CloseStream(0),       // Close oldest
                Operation::CreateStream,         // Now should succeed
                Operation::UpdateLimit(Some(0)), // Block all
                Operation::CreateStream,         // Should be blocked
                Operation::UpdateLimit(Some(5)), // Allow more
                Operation::CreateStream,         // Should succeed
            ],
            max_frame_size: 16384,
        };

        let results = process_input(&input);

        // Verify expected sequence
        assert!(matches!(
            results[1],
            ParseResult::StreamCreationAttempt(StreamCreationResult::Success(_))
        ));
        assert!(matches!(
            results[2],
            ParseResult::StreamCreationAttempt(StreamCreationResult::Success(_))
        ));
        assert!(matches!(
            results[3],
            ParseResult::StreamCreationAttempt(StreamCreationResult::Blocked(_))
        ));
        // After close and limit changes...
        assert!(matches!(
            results[5],
            ParseResult::StreamCreationAttempt(StreamCreationResult::Success(_))
        ));
        assert!(matches!(
            results[7],
            ParseResult::StreamCreationAttempt(StreamCreationResult::Blocked(_))
        ));
        assert!(matches!(
            results[9],
            ParseResult::StreamCreationAttempt(StreamCreationResult::Success(_))
        ));
    }
}
