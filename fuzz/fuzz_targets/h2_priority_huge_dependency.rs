#![no_main]

//! Fuzz target: HTTP/2 PRIORITY frame dependency on closed streams
//!
//! Tests PRIORITY frames where a stream depends on a stream ID that has been
//! closed long ago. Per RFC 7540 §5.3.2, this is permitted behavior - the
//! parser should treat the closed stream as not being in the dependency graph
//! and handle it gracefully without crashing.
//!
//! Key behaviors tested:
//! - PRIORITY dependency on recently closed stream (graceful handling)
//! - PRIORITY dependency on long-closed stream (graceful handling)
//! - PRIORITY dependency on never-existed stream (graceful handling)
//! - Large stream ID gaps in dependency chains
//! - Multiple PRIORITY updates referencing closed streams
//! - Stream lifecycle and dependency graph management

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

/// HTTP/2 frame type identifiers
#[cfg(test)]
const PRIORITY_TYPE: u8 = 0x2;

/// HTTP/2 stream states per RFC 7540 §5.1
#[derive(Debug, Clone, PartialEq)]
enum StreamState {
    Open,
    Closed,
}

/// Stream entry with priority information
#[derive(Debug, Clone)]
struct StreamEntry {
    stream_id: u32,
    state: StreamState,
    depends_on: Option<u32>,
    weight: u8,
    exclusive: bool,
    closed_at: Option<u64>, // Timestamp when closed (for testing "long ago" behavior)
}

/// Priority dependency information
#[derive(Debug, Clone)]
struct PriorityInfo {
    exclusive: bool,
    stream_dependency: u32,
    weight: u8, // 1-256 (wire format is 0-255)
}

/// Mock parser for HTTP/2 PRIORITY frame validation
#[derive(Debug)]
struct MockH2PriorityParser {
    streams: Vec<StreamEntry>,
    current_time: u64,
}

/// Result types for parsing
#[derive(Debug, PartialEq)]
enum ParseResult {
    /// PRIORITY frame processed successfully
    PriorityProcessed {
        stream_id: u32,
        depends_on: Option<u32>,
        weight: u8,
    },
    /// Stream created
    StreamCreated(u32),
    /// Stream closed
    StreamClosed { stream_id: u32, time: u64 },
    /// Protocol error (should be rare for PRIORITY)
    ProtocolError(String),
    /// Frame processed (other frame types)
    FrameProcessed,
}

/// Input for fuzz testing
#[derive(Debug, Arbitrary)]
struct H2PriorityDependencyInput {
    /// Initial streams to create
    initial_streams: Vec<u32>,

    /// Sequence of operations to test
    operations: Vec<PriorityOperation>,

    /// Time advancement between operations (simulates "long ago")
    #[arbitrary(with = |u: &mut arbitrary::Unstructured| u.int_in_range(1..=1000))]
    time_advance_step: u64,
}

#[derive(Debug, Arbitrary)]
enum PriorityOperation {
    /// Send PRIORITY frame
    SetPriority {
        stream_id: u32,
        depends_on: u32,
        weight: u8, // 0-255 (wire format)
        exclusive: bool,
    },
    /// Create a new stream
    CreateStream(u32),
    /// Close an existing stream
    CloseStream(u32),
    /// Advance time (simulates "long ago" closed streams)
    AdvanceTime(u64),
    /// Send multiple PRIORITY frames in sequence
    PriorityBatch {
        updates: Vec<(u32, u32, u8, bool)>, // (stream_id, depends_on, weight, exclusive)
    },
}

impl MockH2PriorityParser {
    fn new() -> Self {
        Self {
            streams: Vec::new(),
            current_time: 0,
        }
    }

    /// Get or create a stream entry
    fn get_or_create_stream(&mut self, stream_id: u32) -> &mut StreamEntry {
        if let Some(pos) = self.streams.iter().position(|s| s.stream_id == stream_id) {
            return &mut self.streams[pos];
        }

        // Create new stream
        self.streams.push(StreamEntry {
            stream_id,
            state: StreamState::Open,
            depends_on: None,
            weight: 16, // Default weight
            exclusive: false,
            closed_at: None,
        });
        self.streams.last_mut().unwrap()
    }

    /// Get existing stream (without creating)
    fn get_stream(&mut self, stream_id: u32) -> Option<&mut StreamEntry> {
        self.streams.iter_mut().find(|s| s.stream_id == stream_id)
    }

    /// Check if a stream exists and is active in the dependency graph
    fn is_stream_in_dependency_graph(&self, stream_id: u32) -> bool {
        self.streams
            .iter()
            .any(|s| s.stream_id == stream_id && s.state != StreamState::Closed)
    }

    /// Process PRIORITY frame
    fn process_priority_frame(&mut self, stream_id: u32, priority: PriorityInfo) -> ParseResult {
        // Stream ID 0 is invalid for PRIORITY frames
        if stream_id == 0 {
            return ParseResult::ProtocolError("PRIORITY frame with stream_id=0".to_string());
        }

        // Self-dependency is not allowed (RFC 7540 §5.3.1)
        if stream_id == priority.stream_dependency {
            return ParseResult::ProtocolError(format!(
                "PRIORITY self-dependency: stream {} depends on itself",
                stream_id
            ));
        }

        // Convert wire weight (0-255) to actual weight (1-256)
        let actual_weight = priority.weight.wrapping_add(1);

        // Handle dependency on closed/non-existent stream
        let dependency_target = if priority.stream_dependency == 0 {
            // Dependency on stream 0 means root of the tree
            None
        } else if self.is_stream_in_dependency_graph(priority.stream_dependency) {
            // Valid active stream dependency
            Some(priority.stream_dependency)
        } else {
            // Per RFC 7540 §5.3.2: If the stream dependency is not in the tree,
            // treat it as depending on stream 0 (root)
            None
        };

        {
            // Get or create the stream (PRIORITY can create streams), then update
            // priority after dependency lookup has finished reading parser state.
            let stream = self.get_or_create_stream(stream_id);
            stream.depends_on = dependency_target;
            stream.weight = actual_weight;
            stream.exclusive = priority.exclusive;
        }

        // Handle exclusive dependency restructuring
        if let (true, Some(target_stream)) = (priority.exclusive, dependency_target) {
            // In exclusive mode, this stream becomes the sole dependent of the target,
            // and all other dependents become dependents of this stream
            // Find all streams that currently depend on the target
            let mut affected_streams = Vec::new();
            for other_stream in &mut self.streams {
                if other_stream.stream_id != stream_id
                    && other_stream.depends_on == Some(target_stream)
                {
                    affected_streams.push(other_stream.stream_id);
                }
            }

            // Make those streams depend on this stream instead
            for affected_id in affected_streams {
                if let Some(affected) = self.get_stream(affected_id) {
                    affected.depends_on = Some(stream_id);
                }
            }
        }

        ParseResult::PriorityProcessed {
            stream_id,
            depends_on: dependency_target,
            weight: actual_weight,
        }
    }

    /// Create a stream explicitly
    fn create_stream(&mut self, stream_id: u32) -> ParseResult {
        self.get_or_create_stream(stream_id);
        ParseResult::StreamCreated(stream_id)
    }

    /// Close a stream
    fn close_stream(&mut self, stream_id: u32) -> ParseResult {
        let current_time = self.current_time;
        if let Some(stream) = self.get_stream(stream_id) {
            stream.state = StreamState::Closed;
            stream.closed_at = Some(current_time);

            // Remove this stream from dependency graph but keep the record
            // for testing "long ago" scenarios
            ParseResult::StreamClosed {
                stream_id,
                time: current_time,
            }
        } else {
            // Closing non-existent stream is allowed (idempotent)
            ParseResult::FrameProcessed
        }
    }

    /// Advance time (for testing "long ago" scenarios)
    fn advance_time(&mut self, delta: u64) {
        self.current_time += delta;
    }

    /// Check for circular dependencies (should not occur after proper handling)
    fn check_circular_dependency(&self, start_stream: u32) -> bool {
        let mut visited = std::collections::HashSet::new();
        let mut current = start_stream;

        while let Some(stream) = self.streams.iter().find(|s| s.stream_id == current) {
            if visited.contains(&current) {
                return true; // Circular dependency found
            }
            visited.insert(current);

            match stream.depends_on {
                Some(parent) => current = parent,
                None => break, // Reached root
            }
        }

        false
    }

    /// Get streams that have been closed for a long time
    #[cfg(test)]
    fn get_long_closed_streams(&self, threshold: u64) -> Vec<u32> {
        self.streams
            .iter()
            .filter(|s| {
                s.state == StreamState::Closed
                    && s.closed_at
                        .map_or(false, |t| self.current_time - t >= threshold)
            })
            .map(|s| s.stream_id)
            .collect()
    }
}

/// Encode PRIORITY frame
#[cfg(test)]
fn encode_priority_frame(stream_id: u32, priority: PriorityInfo) -> Vec<u8> {
    let mut frame = Vec::new();
    let payload_len = 5; // PRIORITY frames are always 5 bytes

    // Frame header (9 bytes)
    frame.extend_from_slice(&(payload_len as u32).to_be_bytes()[1..4]); // Length (24 bits)
    frame.push(PRIORITY_TYPE); // Type
    frame.push(0); // Flags (PRIORITY has no flags)
    frame.extend_from_slice(&stream_id.to_be_bytes()); // Stream ID

    // PRIORITY payload (5 bytes)
    let mut dependency_and_exclusive = priority.stream_dependency;
    if priority.exclusive {
        dependency_and_exclusive |= 0x80000000; // Set exclusive bit
    }
    frame.extend_from_slice(&dependency_and_exclusive.to_be_bytes()); // Dependency + E bit
    frame.push(priority.weight); // Weight (wire format: 0-255)

    frame
}

/// Process the input through our mock parser
fn process_input(input: &H2PriorityDependencyInput) -> Vec<ParseResult> {
    let mut parser = MockH2PriorityParser::new();
    let mut results = Vec::new();

    // Create initial streams
    for &stream_id in &input.initial_streams {
        results.push(parser.create_stream(stream_id));
    }

    // Process operations
    for operation in &input.operations {
        parser.advance_time(input.time_advance_step);

        match operation {
            PriorityOperation::SetPriority {
                stream_id,
                depends_on,
                weight,
                exclusive,
            } => {
                let priority = PriorityInfo {
                    exclusive: *exclusive,
                    stream_dependency: *depends_on,
                    weight: *weight,
                };
                let result = parser.process_priority_frame(*stream_id, priority);
                results.push(result);
            }
            PriorityOperation::CreateStream(stream_id) => {
                results.push(parser.create_stream(*stream_id));
            }
            PriorityOperation::CloseStream(stream_id) => {
                results.push(parser.close_stream(*stream_id));
            }
            PriorityOperation::AdvanceTime(delta) => {
                parser.advance_time(*delta);
                // Don't add result for time advancement
            }
            PriorityOperation::PriorityBatch { updates } => {
                for &(stream_id, depends_on, weight, exclusive) in updates {
                    let priority = PriorityInfo {
                        exclusive,
                        stream_dependency: depends_on,
                        weight,
                    };
                    let result = parser.process_priority_frame(stream_id, priority);
                    results.push(result);
                }
            }
        }
    }

    results
}

fn assert_priority_results(results: &[ParseResult], context: &str) {
    // Track closed streams and verify PRIORITY never keeps a closed dependency
    // in the active dependency graph.
    let mut closed_streams = std::collections::HashSet::new();

    for result in results {
        match result {
            ParseResult::StreamClosed { stream_id, .. } => {
                closed_streams.insert(*stream_id);
            }
            ParseResult::PriorityProcessed {
                stream_id,
                depends_on: Some(dep_stream),
                ..
            } => {
                assert!(
                    !closed_streams.contains(dep_stream),
                    "{context}: PRIORITY processing included closed stream {dep_stream} as dependency for stream {stream_id}"
                );
            }
            ParseResult::PriorityProcessed { .. } => {}
            ParseResult::ProtocolError(msg) => {
                assert!(
                    is_expected_priority_protocol_error(msg),
                    "{context}: unexpected PRIORITY protocol error: {msg}"
                );
            }
            _ => {}
        }
    }
}

fn is_expected_priority_protocol_error(msg: &str) -> bool {
    msg.contains("self-dependency") || msg.contains("stream_id=0")
}

fn assert_predefined_priority_processed(
    parser: &MockH2PriorityParser,
    stream_id: u32,
    result: ParseResult,
    context: &str,
) {
    match result {
        ParseResult::PriorityProcessed { .. } => {}
        ParseResult::ProtocolError(msg) => {
            panic!("{context}: unexpected protocol error for stream {stream_id}: {msg}");
        }
        other => {
            panic!("{context}: expected PRIORITY processing for stream {stream_id}, got {other:?}");
        }
    }

    assert!(
        !parser.check_circular_dependency(stream_id),
        "{context}: circular dependency created for stream {stream_id}"
    );
}

fuzz_target!(|input: H2PriorityDependencyInput| {
    // Skip empty inputs
    if input.operations.is_empty() {
        return;
    }

    let results = process_input(&input);
    assert_priority_results(&results, "arbitrary input");

    // Test specific closed stream dependency scenarios
    let closed_dependency_tests = [
        // Stream depends on a stream that was just closed
        vec![
            PriorityOperation::CreateStream(1),
            PriorityOperation::CreateStream(3),
            PriorityOperation::CloseStream(3),
            PriorityOperation::SetPriority {
                stream_id: 1,
                depends_on: 3,
                weight: 100,
                exclusive: false,
            },
        ],
        // Stream depends on a stream closed "long ago"
        vec![
            PriorityOperation::CreateStream(5),
            PriorityOperation::CreateStream(7),
            PriorityOperation::CloseStream(7),
            PriorityOperation::AdvanceTime(10000), // Long time passes
            PriorityOperation::SetPriority {
                stream_id: 5,
                depends_on: 7,
                weight: 50,
                exclusive: true,
            },
        ],
        // Stream depends on a never-existed stream
        vec![
            PriorityOperation::CreateStream(9),
            PriorityOperation::SetPriority {
                stream_id: 9,
                depends_on: 999999,
                weight: 25,
                exclusive: false,
            },
        ],
        // Chain of dependencies through closed streams
        vec![
            PriorityOperation::CreateStream(11),
            PriorityOperation::CreateStream(13),
            PriorityOperation::CreateStream(15),
            PriorityOperation::CloseStream(13),
            PriorityOperation::SetPriority {
                stream_id: 11,
                depends_on: 13,
                weight: 80,
                exclusive: false,
            },
            PriorityOperation::SetPriority {
                stream_id: 15,
                depends_on: 11,
                weight: 120,
                exclusive: true,
            },
        ],
    ];

    for test_ops in closed_dependency_tests {
        let test_input = H2PriorityDependencyInput {
            initial_streams: vec![],
            operations: test_ops,
            time_advance_step: 100,
        };

        let test_results = process_input(&test_input);
        assert_priority_results(&test_results, "predefined closed-dependency case");

        // Verify no parser state corruption
        let mut test_parser = MockH2PriorityParser::new();
        for operation in &test_input.operations {
            match operation {
                PriorityOperation::SetPriority {
                    stream_id,
                    depends_on,
                    weight,
                    exclusive,
                } => {
                    let priority = PriorityInfo {
                        exclusive: *exclusive,
                        stream_dependency: *depends_on,
                        weight: *weight,
                    };
                    let result = test_parser.process_priority_frame(*stream_id, priority);
                    let context = "predefined closed-dependency SetPriority";
                    assert_predefined_priority_processed(&test_parser, *stream_id, result, context);
                }
                PriorityOperation::CreateStream(stream_id) => {
                    test_parser.create_stream(*stream_id);
                }
                PriorityOperation::CloseStream(stream_id) => {
                    test_parser.close_stream(*stream_id);
                }
                PriorityOperation::AdvanceTime(delta) => {
                    test_parser.advance_time(*delta);
                }
                PriorityOperation::PriorityBatch { updates } => {
                    for &(stream_id, depends_on, weight, exclusive) in updates {
                        let priority = PriorityInfo {
                            exclusive,
                            stream_dependency: depends_on,
                            weight,
                        };
                        let result = test_parser.process_priority_frame(stream_id, priority);
                        let context = "predefined closed-dependency PriorityBatch";
                        assert_predefined_priority_processed(
                            &test_parser,
                            stream_id,
                            result,
                            context,
                        );
                    }
                }
            }
        }
    }
});

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_priority_on_closed_stream() {
        let mut parser = MockH2PriorityParser::new();

        // Create and close stream 3
        parser.create_stream(3);
        parser.close_stream(3);

        // Create stream 1 and set priority to depend on closed stream 3
        parser.create_stream(1);
        let priority = PriorityInfo {
            exclusive: false,
            stream_dependency: 3,
            weight: 100,
        };

        let result = parser.process_priority_frame(1, priority);

        // Should succeed, with dependency treated as root (None)
        match result {
            ParseResult::PriorityProcessed { depends_on, .. } => {
                assert_eq!(
                    depends_on, None,
                    "Closed stream dependency should be treated as root"
                );
            }
            other => panic!("Expected priority processed, got: {:?}", other),
        }
    }

    #[test]
    fn test_priority_on_nonexistent_stream() {
        let mut parser = MockH2PriorityParser::new();

        // Create stream 1 and set priority to depend on never-existed stream 999
        parser.create_stream(1);
        let priority = PriorityInfo {
            exclusive: false,
            stream_dependency: 999,
            weight: 50,
        };

        let result = parser.process_priority_frame(1, priority);

        // Should succeed, with dependency treated as root (None)
        match result {
            ParseResult::PriorityProcessed { depends_on, .. } => {
                assert_eq!(
                    depends_on, None,
                    "Non-existent stream dependency should be treated as root"
                );
            }
            other => panic!("Expected priority processed, got: {:?}", other),
        }
    }

    #[test]
    fn test_exclusive_priority_with_closed_dependency() {
        let mut parser = MockH2PriorityParser::new();

        // Create streams
        parser.create_stream(1);
        parser.create_stream(3);
        parser.create_stream(5);

        // Close stream 3
        parser.close_stream(3);

        // Set exclusive priority on closed stream
        let priority = PriorityInfo {
            exclusive: true,
            stream_dependency: 3,
            weight: 200,
        };

        let result = parser.process_priority_frame(5, priority);

        // Should handle gracefully
        assert!(matches!(result, ParseResult::PriorityProcessed { .. }));
    }

    #[test]
    fn test_self_dependency_rejection() {
        let mut parser = MockH2PriorityParser::new();

        // Create stream 1
        parser.create_stream(1);

        // Try to make stream 1 depend on itself
        let priority = PriorityInfo {
            exclusive: false,
            stream_dependency: 1,
            weight: 100,
        };

        let result = parser.process_priority_frame(1, priority);

        // Should be protocol error
        match result {
            ParseResult::ProtocolError(msg) => {
                assert!(msg.contains("self-dependency"));
            }
            other => panic!(
                "Expected protocol error for self-dependency, got: {:?}",
                other
            ),
        }
    }

    #[test]
    fn test_circular_dependency_prevention() {
        let mut parser = MockH2PriorityParser::new();

        // Create streams: 1 -> 3 -> 5 -> (try to create cycle back to 1)
        parser.create_stream(1);
        parser.create_stream(3);
        parser.create_stream(5);

        // Set up: 3 depends on 1
        let priority = PriorityInfo {
            exclusive: false,
            stream_dependency: 1,
            weight: 100,
        };
        parser.process_priority_frame(3, priority);

        // Set up: 5 depends on 3
        let priority = PriorityInfo {
            exclusive: false,
            stream_dependency: 3,
            weight: 100,
        };
        parser.process_priority_frame(5, priority);

        // No circular dependency yet
        assert!(!parser.check_circular_dependency(1));
        assert!(!parser.check_circular_dependency(3));
        assert!(!parser.check_circular_dependency(5));
    }

    #[test]
    fn test_long_closed_stream_dependency() {
        let mut parser = MockH2PriorityParser::new();

        // Create and close stream 7
        parser.create_stream(7);
        parser.close_stream(7);

        // Advance time significantly
        parser.advance_time(50000);

        // Verify it's in the "long closed" list
        let long_closed = parser.get_long_closed_streams(1000);
        assert!(long_closed.contains(&7));

        // Create new stream and depend on long-closed stream
        parser.create_stream(9);
        let priority = PriorityInfo {
            exclusive: false,
            stream_dependency: 7,
            weight: 75,
        };

        let result = parser.process_priority_frame(9, priority);

        // Should handle gracefully
        match result {
            ParseResult::PriorityProcessed { depends_on, .. } => {
                assert_eq!(
                    depends_on, None,
                    "Long-closed stream should be treated as root dependency"
                );
            }
            other => panic!(
                "Expected priority processed for long-closed dependency, got: {:?}",
                other
            ),
        }
    }

    #[test]
    fn test_priority_frame_encoding() {
        let priority = PriorityInfo {
            exclusive: true,
            stream_dependency: 42,
            weight: 150,
        };

        let frame = encode_priority_frame(7, priority);

        // Check frame header
        assert_eq!(frame[3], PRIORITY_TYPE);
        assert_eq!(frame[4], 0); // No flags
        assert_eq!(
            u32::from_be_bytes([frame[5], frame[6], frame[7], frame[8]]),
            7
        ); // Stream ID

        // Check priority payload
        let dependency_and_exclusive =
            u32::from_be_bytes([frame[9], frame[10], frame[11], frame[12]]);
        assert_eq!(dependency_and_exclusive & 0x7FFFFFFF, 42); // Dependency
        assert_eq!(dependency_and_exclusive & 0x80000000, 0x80000000); // Exclusive bit
        assert_eq!(frame[13], 150); // Weight
    }

    #[test]
    fn test_weight_conversion() {
        let mut parser = MockH2PriorityParser::new();
        parser.create_stream(1);

        // Wire weight 0 should become actual weight 1
        let priority = PriorityInfo {
            exclusive: false,
            stream_dependency: 0,
            weight: 0, // Wire format
        };

        let result = parser.process_priority_frame(1, priority);
        match result {
            ParseResult::PriorityProcessed { weight, .. } => {
                assert_eq!(weight, 1); // Actual weight
            }
            other => panic!("Expected priority processed, got: {:?}", other),
        }

        // Wire weight 255 should become actual weight 256
        let priority = PriorityInfo {
            exclusive: false,
            stream_dependency: 0,
            weight: 255, // Wire format
        };

        let result = parser.process_priority_frame(1, priority);
        match result {
            ParseResult::PriorityProcessed { weight, .. } => {
                assert_eq!(weight, 256); // Actual weight (255 + 1)
            }
            other => panic!("Expected priority processed, got: {:?}", other),
        }
    }

    #[test]
    fn test_massive_stream_id_gaps() {
        let mut parser = MockH2PriorityParser::new();

        // Create streams with large ID gaps
        let large_ids = [1, 1000000, 2000000000, u32::MAX - 1];

        for &stream_id in &large_ids {
            parser.create_stream(stream_id);
        }

        // Close some streams
        parser.close_stream(1000000);
        parser.close_stream(u32::MAX - 1);

        // Set priority with closed huge stream ID dependency
        let priority = PriorityInfo {
            exclusive: false,
            stream_dependency: u32::MAX - 1,
            weight: 42,
        };

        let result = parser.process_priority_frame(1, priority);

        // Should handle gracefully despite huge stream ID
        assert!(matches!(result, ParseResult::PriorityProcessed { .. }));
    }
}
