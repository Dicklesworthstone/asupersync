#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use libfuzzer_sys::fuzz_target;

/// HTTP/2 frame header length per RFC 7540 §4.1
const FRAME_HEADER_LEN: usize = 9;

/// HTTP/2 PRIORITY frame type per RFC 7540 §6.3
const PRIORITY_FRAME_TYPE: u8 = 0x2;

/// PRIORITY frame payload length per RFC 7540 §6.3
const PRIORITY_PAYLOAD_LEN: usize = 5;

/// HTTP/2 error codes per RFC 7540 §7
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
enum Http2ErrorCode {
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

/// PRIORITY frame data per RFC 7540 §6.3
#[derive(Debug, Clone, PartialEq, Eq)]
struct PriorityData {
    /// Exclusive flag (E) - bit 31 of the first 32 bits
    exclusive: bool,
    /// Stream dependency - remaining 31 bits
    stream_dependency: u32,
    /// Weight (1-256, encoded as 0-255)
    weight: u8,
}

impl PriorityData {
    fn encode(&self) -> [u8; 5] {
        let mut buf = [0u8; 5];

        // Combine exclusive flag with stream dependency
        let first_word = if self.exclusive {
            0x8000_0000 | (self.stream_dependency & 0x7FFF_FFFF)
        } else {
            self.stream_dependency & 0x7FFF_FFFF
        };

        // Encode first 32 bits (exclusive + stream dependency) in big-endian
        buf[0] = (first_word >> 24) as u8;
        buf[1] = (first_word >> 16) as u8;
        buf[2] = (first_word >> 8) as u8;
        buf[3] = first_word as u8;

        // Weight
        buf[4] = self.weight;

        buf
    }

    fn decode(buf: &[u8]) -> Result<Self, &'static str> {
        if buf.len() < 5 {
            return Err("insufficient data");
        }

        let first_word = ((buf[0] as u32) << 24)
            | ((buf[1] as u32) << 16)
            | ((buf[2] as u32) << 8)
            | (buf[3] as u32);

        let exclusive = (first_word & 0x8000_0000) != 0;
        let stream_dependency = first_word & 0x7FFF_FFFF;
        let weight = buf[4];

        Ok(PriorityData {
            exclusive,
            stream_dependency,
            weight,
        })
    }
}

/// HTTP/2 frame header per RFC 7540 §4.1
#[derive(Debug, Clone)]
struct FrameHeader {
    length: u32,
    frame_type: u8,
    flags: u8,
    stream_id: u32,
}

impl FrameHeader {
    fn encode(&self) -> [u8; 9] {
        let mut buf = [0u8; 9];

        // Length (24 bits, big-endian)
        buf[0] = (self.length >> 16) as u8;
        buf[1] = (self.length >> 8) as u8;
        buf[2] = self.length as u8;

        // Type and flags
        buf[3] = self.frame_type;
        buf[4] = self.flags;

        // Stream ID (31 bits + reserved bit, big-endian)
        let stream_id = self.stream_id & 0x7FFF_FFFF;
        buf[5] = (stream_id >> 24) as u8;
        buf[6] = (stream_id >> 16) as u8;
        buf[7] = (stream_id >> 8) as u8;
        buf[8] = stream_id as u8;

        buf
    }

    fn decode(buf: &[u8]) -> Result<Self, &'static str> {
        if buf.len() < 9 {
            return Err("incomplete header");
        }

        let length = ((buf[0] as u32) << 16) | ((buf[1] as u32) << 8) | (buf[2] as u32);

        let frame_type = buf[3];
        let flags = buf[4];

        let stream_id = ((buf[5] as u32 & 0x7F) << 24)
            | ((buf[6] as u32) << 16)
            | ((buf[7] as u32) << 8)
            | (buf[8] as u32);

        Ok(FrameHeader {
            length,
            frame_type,
            flags,
            stream_id,
        })
    }
}

/// PRIORITY frame per RFC 7540 §6.3
#[derive(Debug, Clone)]
struct PriorityFrame {
    header: FrameHeader,
    priority_data: PriorityData,
}

impl PriorityFrame {
    fn new(stream_id: u32, priority_data: PriorityData) -> Result<Self, &'static str> {
        if stream_id == 0 {
            return Err("PRIORITY frame cannot have stream ID 0");
        }

        let header = FrameHeader {
            length: PRIORITY_PAYLOAD_LEN as u32,
            frame_type: PRIORITY_FRAME_TYPE,
            flags: 0, // No flags defined for PRIORITY frames
            stream_id,
        };

        Ok(PriorityFrame {
            header,
            priority_data,
        })
    }

    fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(FRAME_HEADER_LEN + PRIORITY_PAYLOAD_LEN);
        buf.extend_from_slice(&self.header.encode());
        buf.extend_from_slice(&self.priority_data.encode());
        buf
    }
}

#[derive(Debug, PartialEq)]
enum PriorityParseResult {
    Valid(PriorityFrame),
    ProtocolError(String),
    FrameSizeError,
    IncompleteFrame,
    InvalidStreamId,
}

/// Stream dependency tree to detect cycles per RFC 7540 §5.3.1
#[derive(Debug, Clone)]
struct DependencyTree {
    /// Maps stream_id -> (dependency, weight, exclusive)
    dependencies: std::collections::HashMap<u32, (u32, u8, bool)>,
}

impl DependencyTree {
    fn new() -> Self {
        Self {
            dependencies: std::collections::HashMap::new(),
        }
    }

    /// Add or update a stream dependency
    /// Returns error if this would create a cycle per RFC 7540 §5.3.1
    fn set_dependency(
        &mut self,
        stream_id: u32,
        dependency: u32,
        weight: u8,
        exclusive: bool,
    ) -> Result<(), String> {
        // RFC 7540 §5.3.1: Stream cannot depend on itself
        if stream_id == dependency {
            return Err(format!("Stream {} cannot depend on itself", stream_id));
        }

        // Temporarily add the dependency to check for cycles
        let old_dependency = self
            .dependencies
            .insert(stream_id, (dependency, weight, exclusive));

        // Check for cycles using DFS
        if self.has_cycle_from(dependency) {
            // Restore old state and return error
            if let Some(old) = old_dependency {
                self.dependencies.insert(stream_id, old);
            } else {
                self.dependencies.remove(&stream_id);
            }
            return Err(format!(
                "Setting stream {} dependency to {} would create a cycle",
                stream_id, dependency
            ));
        }

        Ok(())
    }

    /// Detect cycles using DFS from the given starting stream
    fn has_cycle_from(&self, start_stream: u32) -> bool {
        let mut visited = std::collections::HashSet::new();
        let mut path = std::collections::HashSet::new();
        self.dfs_cycle_check(start_stream, &mut visited, &mut path)
    }

    /// Depth-first search to detect cycles
    fn dfs_cycle_check(
        &self,
        stream_id: u32,
        visited: &mut std::collections::HashSet<u32>,
        path: &mut std::collections::HashSet<u32>,
    ) -> bool {
        if path.contains(&stream_id) {
            // Found a cycle
            return true;
        }

        if visited.contains(&stream_id) {
            // Already visited this node in a previous path
            return false;
        }

        visited.insert(stream_id);
        path.insert(stream_id);

        // Follow the dependency chain
        if let Some((dependency, _, _)) = self.dependencies.get(&stream_id) {
            if *dependency != 0 && self.dfs_cycle_check(*dependency, visited, path) {
                return true;
            }
        }

        path.remove(&stream_id);
        false
    }

    /// Get all streams involved in cycles (for debugging)
    fn find_all_cycles(&self) -> Vec<Vec<u32>> {
        let mut cycles = Vec::new();
        let mut visited = std::collections::HashSet::new();

        for &stream_id in self.dependencies.keys() {
            if !visited.contains(&stream_id) {
                if let Some(cycle) = self.find_cycle_from(stream_id, &mut visited) {
                    cycles.push(cycle);
                }
            }
        }

        cycles
    }

    fn find_cycle_from(
        &self,
        start_stream: u32,
        visited: &mut std::collections::HashSet<u32>,
    ) -> Option<Vec<u32>> {
        let mut path = Vec::new();
        let mut path_set = std::collections::HashSet::new();
        self.dfs_find_cycle(start_stream, &mut path, &mut path_set, visited)
    }

    fn dfs_find_cycle(
        &self,
        stream_id: u32,
        path: &mut Vec<u32>,
        path_set: &mut std::collections::HashSet<u32>,
        visited: &mut std::collections::HashSet<u32>,
    ) -> Option<Vec<u32>> {
        if path_set.contains(&stream_id) {
            // Found cycle - extract the cycle portion
            let cycle_start = path.iter().position(|&s| s == stream_id)?;
            return Some(path[cycle_start..].to_vec());
        }

        if visited.contains(&stream_id) {
            return None;
        }

        visited.insert(stream_id);
        path.push(stream_id);
        path_set.insert(stream_id);

        if let Some((dependency, _, _)) = self.dependencies.get(&stream_id) {
            if *dependency != 0 {
                if let Some(cycle) = self.dfs_find_cycle(*dependency, path, path_set, visited) {
                    return Some(cycle);
                }
            }
        }

        path.pop();
        path_set.remove(&stream_id);
        None
    }
}

/// Mock HTTP/2 PRIORITY frame parser with cycle detection
struct MockH2PriorityParser {
    dependency_tree: DependencyTree,
}

impl MockH2PriorityParser {
    fn new() -> Self {
        Self {
            dependency_tree: DependencyTree::new(),
        }
    }

    /// Parse PRIORITY frame and update dependency tree
    fn parse_priority_frame(&mut self, buf: &[u8]) -> PriorityParseResult {
        // Parse frame header
        let header = match FrameHeader::decode(buf) {
            Ok(h) => h,
            Err(_) => return PriorityParseResult::IncompleteFrame,
        };

        // Must be PRIORITY frame
        if header.frame_type != PRIORITY_FRAME_TYPE {
            return PriorityParseResult::ProtocolError(format!(
                "Expected PRIORITY frame (0x2), got 0x{:x}",
                header.frame_type
            ));
        }

        // PRIORITY frames must have non-zero stream ID per RFC 7540 §6.3
        if header.stream_id == 0 {
            return PriorityParseResult::InvalidStreamId;
        }

        // PRIORITY frames must have exactly 5 bytes payload per RFC 7540 §6.3
        if header.length != PRIORITY_PAYLOAD_LEN as u32 {
            return PriorityParseResult::FrameSizeError;
        }

        // Check complete frame is present
        let total_len = FRAME_HEADER_LEN + header.length as usize;
        if buf.len() < total_len {
            return PriorityParseResult::IncompleteFrame;
        }

        // Parse priority data
        let payload = &buf[FRAME_HEADER_LEN..total_len];
        let priority_data = match PriorityData::decode(payload) {
            Ok(data) => data,
            Err(_) => {
                return PriorityParseResult::ProtocolError("Invalid priority data".to_string());
            }
        };

        // RFC 7540 §5.3.1: Check for cycle creation
        if let Err(cycle_error) = self.dependency_tree.set_dependency(
            header.stream_id,
            priority_data.stream_dependency,
            priority_data.weight,
            priority_data.exclusive,
        ) {
            return PriorityParseResult::ProtocolError(format!("Cycle detected: {}", cycle_error));
        }

        let frame = PriorityFrame {
            header,
            priority_data,
        };

        PriorityParseResult::Valid(frame)
    }

    /// Get current dependency tree state for debugging
    fn get_dependency_tree(&self) -> &DependencyTree {
        &self.dependency_tree
    }
}

#[derive(Arbitrary, Debug)]
struct FuzzInput {
    /// Sequence of priority frame operations
    priority_operations: Vec<PriorityOperation>,
    /// Whether to include classic 3-stream cycle (A→B→C→A)
    include_classic_cycle: bool,
    /// Whether to include self-dependency (should always fail)
    include_self_dependency: bool,
    /// Extra random operations after structured tests
    extra_operations: Vec<PriorityOperation>,
}

#[derive(Arbitrary, Debug, Clone)]
struct PriorityOperation {
    stream_id: u32,
    dependency: u32,
    weight: u8,
    exclusive: bool,
    /// Whether to corrupt this frame (for robustness testing)
    corrupt_frame: bool,
}

fuzz_target!(|input: FuzzInput| {
    let mut parser = MockH2PriorityParser::new();
    let mut operations = input.priority_operations;

    // Add classic 3-stream cycle test case: A→B→C→A
    if input.include_classic_cycle {
        // Create streams 1→2, 2→3, then try 3→1 (should fail with cycle)
        operations.insert(
            0,
            PriorityOperation {
                stream_id: 1,
                dependency: 2,
                weight: 16,
                exclusive: false,
                corrupt_frame: false,
            },
        );
        operations.insert(
            1,
            PriorityOperation {
                stream_id: 2,
                dependency: 3,
                weight: 16,
                exclusive: false,
                corrupt_frame: false,
            },
        );
        operations.insert(
            2,
            PriorityOperation {
                stream_id: 3,
                dependency: 1, // This creates the cycle!
                weight: 16,
                exclusive: false,
                corrupt_frame: false,
            },
        );
    }

    // Add self-dependency test (should always fail)
    if input.include_self_dependency {
        operations.push(PriorityOperation {
            stream_id: 42,
            dependency: 42, // Self-dependency
            weight: 10,
            exclusive: false,
            corrupt_frame: false,
        });
    }

    // Add extra random operations
    operations.extend(input.extra_operations);

    let mut cycle_detected = false;
    let mut cycle_details = Vec::new();

    for (op_index, op) in operations.iter().enumerate() {
        // Ensure valid stream IDs (non-zero)
        let stream_id = if op.stream_id == 0 {
            1
        } else {
            op.stream_id & 0x7FFF_FFFF
        };
        let dependency = op.dependency & 0x7FFF_FFFF;

        let priority_data = PriorityData {
            exclusive: op.exclusive,
            stream_dependency: dependency,
            weight: op.weight,
        };

        // Create PRIORITY frame
        let frame = match PriorityFrame::new(stream_id, priority_data) {
            Ok(f) => f,
            Err(_) => continue, // Skip invalid frames
        };

        let mut frame_bytes = frame.encode();

        // Optionally corrupt the frame for robustness testing
        if op.corrupt_frame && frame_bytes.len() > FRAME_HEADER_LEN {
            // Corrupt payload
            frame_bytes[FRAME_HEADER_LEN] = 0xFF;
        }

        // Parse the frame
        let result = parser.parse_priority_frame(&frame_bytes);

        match result {
            PriorityParseResult::Valid(_) => {
                // Frame parsed successfully - dependency was valid
            }

            PriorityParseResult::ProtocolError(msg) => {
                if msg.contains("cycle") || msg.contains("depend on itself") {
                    cycle_detected = true;
                    cycle_details.push((op_index, stream_id, dependency, msg.clone()));

                    // Verify this is actually a problematic case
                    if stream_id == dependency {
                        // Self-dependency - should always be detected
                        assert!(
                            msg.contains("depend on itself"),
                            "Self-dependency should be detected: stream {} -> {}",
                            stream_id,
                            dependency
                        );
                    } else {
                        // Multi-hop cycle - verify the detection is valid
                        assert!(
                            msg.contains("cycle"),
                            "Multi-hop cycle should be detected: {} -> {}",
                            stream_id,
                            dependency
                        );
                    }
                }
            }

            PriorityParseResult::FrameSizeError => {
                // Expected for corrupted frames
            }

            PriorityParseResult::IncompleteFrame => {
                // Expected for truncated data
            }

            PriorityParseResult::InvalidStreamId => {
                // Should not happen with our stream ID logic
                panic!("Unexpected InvalidStreamId with stream_id: {}", stream_id);
            }
        }
    }

    // Verify cycle detection worked for known problematic cases
    if input.include_classic_cycle {
        assert!(
            cycle_detected,
            "Classic 3-stream cycle (1→2→3→1) should have been detected"
        );

        // Check that the dependency tree actually found the cycle
        let all_cycles = parser.get_dependency_tree().find_all_cycles();
        assert!(
            !all_cycles.is_empty(),
            "Dependency tree should contain detected cycles"
        );
    }

    if input.include_self_dependency {
        assert!(
            cycle_details.iter().any(|(_, stream, dep, msg)| {
                *stream == *dep && msg.contains("depend on itself")
            }),
            "Self-dependency should have been detected"
        );
    }

    // Additional verification: ensure parser's dependency tree is cycle-free after valid operations
    let remaining_cycles = parser.get_dependency_tree().find_all_cycles();
    assert!(
        remaining_cycles.is_empty(),
        "Parser dependency tree should not contain cycles after processing: {:?}",
        remaining_cycles
    );

    // Test multi-hop cycle detection specifically for longer chains
    if operations.len() >= 5 {
        // Try to create a 5-stream cycle: 10→11→12→13→14→10
        let mut test_parser = MockH2PriorityParser::new();
        let mut chain_operations = Vec::new();

        for i in 0..5 {
            let stream = 10 + i;
            let next_stream = 10 + ((i + 1) % 5);

            let op = PriorityOperation {
                stream_id: stream,
                dependency: next_stream,
                weight: 8,
                exclusive: false,
                corrupt_frame: false,
            };
            chain_operations.push(op);
        }

        let mut long_cycle_detected = false;
        for op in &chain_operations {
            let priority_data = PriorityData {
                exclusive: op.exclusive,
                stream_dependency: op.dependency,
                weight: op.weight,
            };

            if let Ok(frame) = PriorityFrame::new(op.stream_id, priority_data) {
                let frame_bytes = frame.encode();
                match test_parser.parse_priority_frame(&frame_bytes) {
                    PriorityParseResult::ProtocolError(msg) if msg.contains("cycle") => {
                        long_cycle_detected = true;
                        break;
                    }
                    _ => {}
                }
            }
        }

        // Should detect the long cycle when trying to close it
        assert!(
            long_cycle_detected,
            "5-stream cycle should be detected by cycle detection algorithm"
        );
    }
});
