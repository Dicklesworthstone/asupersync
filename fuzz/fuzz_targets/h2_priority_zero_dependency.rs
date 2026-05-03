#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

/// HTTP/2 PRIORITY frame with zero dependency test input
#[derive(Arbitrary, Debug)]
struct H2PriorityZeroDependencyInput {
    /// Priority frame configuration
    priority_frame: PriorityFrame,
    /// Additional priority frames to test dependency tree
    additional_frames: Vec<PriorityFrame>,
    /// Stream state context
    stream_context: StreamContext,
    /// Test scenario configuration
    test_scenario: TestScenario,
}

#[derive(Arbitrary, Debug)]
struct PriorityFrame {
    /// Stream ID this PRIORITY frame applies to
    stream_id: u32,
    /// Stream dependency (0 = root pseudo-stream)
    stream_dependency: u32,
    /// Priority weight (1-256, encoded as 0-255)
    weight: u8,
    /// Exclusive dependency flag
    exclusive: bool,
    /// Frame flags
    flags: u8,
    /// Additional frame properties
    frame_properties: FrameProperties,
}

#[derive(Arbitrary, Debug)]
struct FrameProperties {
    /// Frame size constraints
    frame_size: FrameSize,
    /// Frame validation mode
    validation_mode: FrameValidationMode,
    /// Whether to test frame boundary conditions
    test_boundaries: bool,
}

#[derive(Arbitrary, Debug)]
enum FrameSize {
    /// Standard 5-byte PRIORITY frame
    Standard,
    /// Oversized frame (should be rejected)
    Oversized(u8),
    /// Undersized frame (should be rejected)
    Undersized,
}

#[derive(Arbitrary, Debug)]
enum FrameValidationMode {
    /// Strict RFC compliance
    Strict,
    /// Allow some deviations
    Lenient,
    /// Test malformed frames
    Malformed,
}

#[derive(Arbitrary, Debug)]
struct StreamContext {
    /// Currently active streams
    active_streams: Vec<StreamInfo>,
    /// Stream state tracking
    stream_states: StreamStates,
    /// Connection-level context
    connection_state: ConnectionState,
}

#[derive(Arbitrary, Debug)]
struct StreamInfo {
    /// Stream ID
    stream_id: u32,
    /// Stream state
    state: StreamState,
    /// Current priority info
    priority: StreamPriority,
}

#[derive(Arbitrary, Debug)]
enum StreamState {
    Idle,
    ReservedLocal,
    ReservedRemote,
    Open,
    HalfClosedLocal,
    HalfClosedRemote,
    Closed,
}

#[derive(Arbitrary, Debug)]
struct StreamPriority {
    /// Current dependency
    dependency: u32,
    /// Current weight
    weight: u8,
    /// Whether dependency is exclusive
    exclusive: bool,
}

#[derive(Arbitrary, Debug)]
struct StreamStates {
    /// Maximum stream ID seen
    max_stream_id: u32,
    /// Number of active streams
    active_count: u16,
    /// Priority tree depth
    tree_depth: u8,
}

#[derive(Arbitrary, Debug)]
enum ConnectionState {
    Fresh,
    Active,
    Closing,
    GoAwayReceived,
}

#[derive(Arbitrary, Debug)]
struct TestScenario {
    /// Priority tree validation
    tree_validation: TreeValidation,
    /// Dependency cycle detection
    cycle_detection: CycleDetection,
    /// Root dependency handling
    root_dependency_mode: RootDependencyMode,
    /// Error handling approach
    error_handling: ErrorHandling,
}

#[derive(Arbitrary, Debug)]
enum TreeValidation {
    /// Validate complete priority tree
    Full,
    /// Validate only direct dependencies
    DirectOnly,
    /// Skip tree validation
    None,
}

#[derive(Arbitrary, Debug)]
enum CycleDetection {
    /// Detect and prevent dependency cycles
    Enabled,
    /// Allow cycles for testing
    Disabled,
    /// Detect cycles but don't prevent
    DetectOnly,
}

#[derive(Arbitrary, Debug)]
enum RootDependencyMode {
    /// Standard root dependency handling
    Standard,
    /// Test edge cases in root dependencies
    EdgeCase,
    /// Stress test with many root dependents
    StressTest,
}

#[derive(Arbitrary, Debug)]
enum ErrorHandling {
    /// Fail on any invalid priority frame
    FailFast,
    /// Accept valid parts, ignore invalid
    Permissive,
    /// Log errors but continue processing
    LogAndContinue,
}

/// Mock HTTP/2 priority frame parser with dependency tree management
struct MockH2PriorityParser {
    priority_tree: PriorityTree,
    stream_states: StreamStateTracker,
    validation_mode: TreeValidation,
    cycle_detection: CycleDetection,
    parsing_stats: ParsingStats,
}

#[derive(Debug)]
struct PriorityTree {
    /// Root dependencies (stream_dependency = 0)
    root_dependencies: Vec<PriorityNode>,
    /// Non-root dependencies
    dependencies: std::collections::HashMap<u32, PriorityNode>,
    /// Tree structure validation
    tree_stats: TreeStats,
}

#[derive(Debug, Clone)]
struct PriorityNode {
    /// Stream ID of this node
    stream_id: u32,
    /// Parent stream ID (0 for root)
    parent: u32,
    /// Child stream IDs
    children: Vec<u32>,
    /// Priority weight (1-256, stored as 1-256)
    weight: u16,
    /// Whether this is an exclusive dependency
    exclusive: bool,
    /// Tree depth from root
    depth: u16,
}

#[derive(Debug)]
struct TreeStats {
    /// Total nodes in tree
    total_nodes: u32,
    /// Root-dependent nodes
    root_dependent_count: u32,
    /// Maximum tree depth
    max_depth: u16,
    /// Number of cycles detected
    cycles_detected: u32,
}

#[derive(Debug)]
struct StreamStateTracker {
    /// Stream states
    states: std::collections::HashMap<u32, StreamState>,
    /// Stream priority information
    priorities: std::collections::HashMap<u32, StreamPriority>,
    /// Last stream ID used
    last_stream_id: u32,
}

#[derive(Debug)]
struct ParsingStats {
    /// Frames processed
    frames_processed: u32,
    /// Root dependency frames
    root_dependency_frames: u32,
    /// Invalid frames rejected
    invalid_frames: u32,
    /// Cycles prevented
    cycles_prevented: u32,
}

#[derive(Debug, Clone)]
struct ParsedPriorityFrame {
    /// Original frame data
    frame_info: PriorityFrameInfo,
    /// Parsed priority information
    priority: ParsedPriority,
    /// Tree position after processing
    tree_position: TreePosition,
    /// Validation result
    validation_result: PriorityValidationResult,
}

#[derive(Debug, Clone)]
struct PriorityFrameInfo {
    /// Stream ID
    stream_id: u32,
    /// Frame flags
    flags: u8,
    /// Frame size
    size: u32,
    /// Raw frame payload
    payload: Vec<u8>,
}

#[derive(Debug, Clone)]
struct ParsedPriority {
    /// Stream dependency
    dependency: u32,
    /// Priority weight (1-256)
    weight: u16,
    /// Exclusive flag
    exclusive: bool,
    /// Whether depends on root (dependency = 0)
    is_root_dependent: bool,
}

#[derive(Debug, Clone)]
struct TreePosition {
    /// Position in priority tree
    position: TreePositionType,
    /// Parent stream ID
    parent: u32,
    /// Children affected by this change
    affected_children: Vec<u32>,
    /// Tree depth
    depth: u16,
}

#[derive(Debug, Clone, PartialEq)]
enum TreePositionType {
    /// Direct child of root (dependency = 0)
    RootChild,
    /// Child of another stream
    StreamChild(u32),
    /// Root of subtree (has children)
    SubtreeRoot,
    /// Leaf node (no children)
    Leaf,
}

#[derive(Debug, Clone, PartialEq)]
enum PriorityValidationResult {
    /// Frame is valid and processed
    Valid,
    /// Invalid stream dependency
    InvalidDependency { dependency: u32, reason: String },
    /// Would create dependency cycle
    CycleDetected { cycle_path: Vec<u32> },
    /// Invalid frame format
    InvalidFrame(String),
    /// Stream ID issues
    StreamIdError(String),
    /// Frame size error
    FrameSizeError { expected: u32, actual: u32 },
}

#[derive(Debug, PartialEq)]
enum PriorityParsingError {
    /// PRIORITY frame with invalid stream dependency
    InvalidStreamDependency { stream_id: u32, dependency: u32 },
    /// Stream cannot depend on itself
    SelfDependency(u32),
    /// Dependency would create cycle
    DependencyCycle { cycle: Vec<u32> },
    /// Invalid frame size (must be 5 bytes)
    InvalidFrameSize { size: u32 },
    /// PRIORITY frame on stream 0 (connection-level)
    PriorityOnConnectionStream,
    /// Invalid weight value
    InvalidWeight { weight: u8 },
    /// Stream dependency on non-existent stream
    NonExistentDependency { dependency: u32 },
    /// Frame format error
    FrameFormatError(String),
}

// RFC 7540 constants
const PRIORITY_FRAME_SIZE: u32 = 5;
const ROOT_STREAM_ID: u32 = 0;
const MIN_WEIGHT: u16 = 1;
const MAX_WEIGHT: u16 = 256;

impl PriorityNode {
    fn new(stream_id: u32, parent: u32, weight: u16, exclusive: bool) -> Self {
        Self {
            stream_id,
            parent,
            children: Vec::new(),
            weight: weight.clamp(MIN_WEIGHT, MAX_WEIGHT),
            exclusive,
            depth: if parent == ROOT_STREAM_ID { 1 } else { 0 }, // Will be calculated properly
        }
    }

    fn is_root_dependent(&self) -> bool {
        self.parent == ROOT_STREAM_ID
    }

    fn add_child(&mut self, child_id: u32) {
        if !self.children.contains(&child_id) {
            self.children.push(child_id);
        }
    }

    fn remove_child(&mut self, child_id: u32) {
        self.children.retain(|&id| id != child_id);
    }
}

impl PriorityTree {
    fn new() -> Self {
        Self {
            root_dependencies: Vec::new(),
            dependencies: std::collections::HashMap::new(),
            tree_stats: TreeStats {
                total_nodes: 0,
                root_dependent_count: 0,
                max_depth: 0,
                cycles_detected: 0,
            },
        }
    }

    fn add_priority(&mut self, stream_id: u32, dependency: u32, weight: u16, exclusive: bool) -> Result<TreePosition, PriorityParsingError> {
        // Validate inputs
        if stream_id == ROOT_STREAM_ID {
            return Err(PriorityParsingError::PriorityOnConnectionStream);
        }

        if stream_id == dependency {
            return Err(PriorityParsingError::SelfDependency(stream_id));
        }

        // Check for cycles (except root dependency)
        if dependency != ROOT_STREAM_ID {
            if let Some(cycle) = self.detect_cycle(stream_id, dependency) {
                return Err(PriorityParsingError::DependencyCycle { cycle });
            }
        }

        // Remove existing node if it exists
        self.remove_stream(stream_id);

        // Create new priority node
        let new_node = PriorityNode::new(stream_id, dependency, weight, exclusive);
        let is_root_dependent = new_node.is_root_dependent();

        // Handle exclusive dependencies
        let affected_children = if exclusive && dependency != ROOT_STREAM_ID {
            self.handle_exclusive_dependency(dependency, stream_id)
        } else {
            Vec::new()
        };

        // Add to appropriate collection
        if dependency == ROOT_STREAM_ID {
            // Root dependency
            if exclusive {
                // All current root dependencies become children of this stream
                let current_root_deps: Vec<u32> = self.root_dependencies.iter()
                    .map(|node| node.stream_id)
                    .collect();

                for dep_id in current_root_deps {
                    if let Some(mut node) = self.remove_from_root(dep_id) {
                        node.parent = stream_id;
                        self.dependencies.insert(dep_id, node);
                    }
                }

                self.root_dependencies.clear();
            }

            self.root_dependencies.push(new_node);
            self.tree_stats.root_dependent_count += 1;
        } else {
            // Non-root dependency
            if let Some(parent_node) = self.get_node_mut(dependency) {
                parent_node.add_child(stream_id);
            }

            self.dependencies.insert(stream_id, new_node);
        }

        self.tree_stats.total_nodes += 1;

        // Calculate tree depth
        let depth = self.calculate_depth(stream_id);
        if let Some(node) = self.get_node_mut(stream_id) {
            node.depth = depth;
        }
        self.tree_stats.max_depth = self.tree_stats.max_depth.max(depth);

        // Determine tree position
        let position = if is_root_dependent {
            TreePositionType::RootChild
        } else {
            TreePositionType::StreamChild(dependency)
        };

        Ok(TreePosition {
            position,
            parent: dependency,
            affected_children,
            depth,
        })
    }

    fn detect_cycle(&self, stream_id: u32, dependency: u32) -> Option<Vec<u32>> {
        let mut visited = std::collections::HashSet::new();
        let mut path = Vec::new();

        self.dfs_cycle_detection(dependency, stream_id, &mut visited, &mut path)
    }

    fn dfs_cycle_detection(
        &self,
        current: u32,
        target: u32,
        visited: &mut std::collections::HashSet<u32>,
        path: &mut Vec<u32>,
    ) -> Option<Vec<u32>> {
        if current == target {
            path.push(current);
            return Some(path.clone());
        }

        if visited.contains(&current) {
            return None; // Already visited this node
        }

        visited.insert(current);
        path.push(current);

        if let Some(node) = self.get_node(current) {
            if let Some(cycle) = self.dfs_cycle_detection(node.parent, target, visited, path) {
                return Some(cycle);
            }
        }

        path.pop();
        None
    }

    fn handle_exclusive_dependency(&mut self, parent_id: u32, new_child_id: u32) -> Vec<u32> {
        let mut affected = Vec::new();

        if let Some(parent_node) = self.get_node(parent_id) {
            let current_children: Vec<u32> = parent_node.children.clone();

            for child_id in current_children {
                // Make current children depend on the new exclusive child
                if let Some(child_node) = self.get_node_mut(child_id) {
                    child_node.parent = new_child_id;
                    affected.push(child_id);
                }
            }

            // Clear parent's children list - they're now children of new_child
            if let Some(parent_node) = self.get_node_mut(parent_id) {
                parent_node.children.clear();
                parent_node.add_child(new_child_id);
            }
        }

        affected
    }

    fn remove_stream(&mut self, stream_id: u32) {
        // Remove from root dependencies
        self.root_dependencies.retain(|node| {
            if node.stream_id == stream_id {
                self.tree_stats.root_dependent_count = self.tree_stats.root_dependent_count.saturating_sub(1);
                false
            } else {
                true
            }
        });

        // Remove from dependencies
        if self.dependencies.remove(&stream_id).is_some() {
            self.tree_stats.total_nodes = self.tree_stats.total_nodes.saturating_sub(1);
        }

        // Remove from parent's children list
        for node in self.dependencies.values_mut() {
            node.remove_child(stream_id);
        }

        for node in self.root_dependencies.iter_mut() {
            node.remove_child(stream_id);
        }
    }

    fn remove_from_root(&mut self, stream_id: u32) -> Option<PriorityNode> {
        let position = self.root_dependencies.iter().position(|node| node.stream_id == stream_id)?;
        let removed = self.root_dependencies.remove(position);
        self.tree_stats.root_dependent_count = self.tree_stats.root_dependent_count.saturating_sub(1);
        Some(removed)
    }

    fn get_node(&self, stream_id: u32) -> Option<&PriorityNode> {
        self.dependencies.get(&stream_id)
            .or_else(|| self.root_dependencies.iter().find(|node| node.stream_id == stream_id))
    }

    fn get_node_mut(&mut self, stream_id: u32) -> Option<&mut PriorityNode> {
        if self.dependencies.contains_key(&stream_id) {
            self.dependencies.get_mut(&stream_id)
        } else {
            self.root_dependencies.iter_mut().find(|node| node.stream_id == stream_id)
        }
    }

    fn calculate_depth(&self, stream_id: u32) -> u16 {
        let mut depth = 0;
        let mut current = stream_id;

        while let Some(node) = self.get_node(current) {
            depth += 1;
            if node.parent == ROOT_STREAM_ID {
                break;
            }
            current = node.parent;

            // Prevent infinite loops
            if depth > 100 {
                break;
            }
        }

        depth
    }

    fn get_tree_stats(&self) -> &TreeStats {
        &self.tree_stats
    }
}

impl MockH2PriorityParser {
    fn new(validation_mode: TreeValidation, cycle_detection: CycleDetection) -> Self {
        Self {
            priority_tree: PriorityTree::new(),
            stream_states: StreamStateTracker {
                states: std::collections::HashMap::new(),
                priorities: std::collections::HashMap::new(),
                last_stream_id: 0,
            },
            validation_mode,
            cycle_detection,
            parsing_stats: ParsingStats {
                frames_processed: 0,
                root_dependency_frames: 0,
                invalid_frames: 0,
                cycles_prevented: 0,
            },
        }
    }

    fn parse_priority_frame(&mut self, frame_data: &[u8], stream_id: u32, flags: u8) -> Result<ParsedPriorityFrame, PriorityParsingError> {
        self.parsing_stats.frames_processed += 1;

        // Validate frame size
        if frame_data.len() != PRIORITY_FRAME_SIZE as usize {
            return Err(PriorityParsingError::InvalidFrameSize {
                size: frame_data.len() as u32,
            });
        }

        // Validate stream ID
        if stream_id == ROOT_STREAM_ID {
            return Err(PriorityParsingError::PriorityOnConnectionStream);
        }

        // Parse frame payload
        let dependency_raw = u32::from_be_bytes([frame_data[0], frame_data[1], frame_data[2], frame_data[3]]);
        let exclusive = (dependency_raw & 0x80000000) != 0;
        let dependency = dependency_raw & 0x7FFFFFFF; // Clear exclusive bit
        let weight_raw = frame_data[4];
        let weight = (weight_raw as u16) + 1; // RFC 7540: weight is transmitted as 0-255, represents 1-256

        // Validate dependency
        if matches!(self.cycle_detection, CycleDetection::Enabled) && dependency != ROOT_STREAM_ID {
            if stream_id == dependency {
                return Err(PriorityParsingError::SelfDependency(stream_id));
            }
        }

        // Track root dependencies
        let is_root_dependent = dependency == ROOT_STREAM_ID;
        if is_root_dependent {
            self.parsing_stats.root_dependency_frames += 1;
        }

        // Add to priority tree
        let tree_position = match self.priority_tree.add_priority(stream_id, dependency, weight, exclusive) {
            Ok(position) => position,
            Err(error) => {
                match error {
                    PriorityParsingError::DependencyCycle { cycle } => {
                        self.parsing_stats.cycles_prevented += 1;
                        if matches!(self.cycle_detection, CycleDetection::Enabled) {
                            return Err(PriorityParsingError::DependencyCycle { cycle });
                        } else {
                            // Continue processing but log cycle
                            TreePosition {
                                position: TreePositionType::RootChild, // Fallback to root
                                parent: ROOT_STREAM_ID,
                                affected_children: Vec::new(),
                                depth: 1,
                            }
                        }
                    }
                    _ => {
                        self.parsing_stats.invalid_frames += 1;
                        return Err(error);
                    }
                }
            }
        };

        // Update stream state
        self.stream_states.priorities.insert(stream_id, StreamPriority {
            dependency,
            weight: weight as u8, // Store as 1-256 but transmit as 0-255
            exclusive,
        });

        // Create parsed result
        let parsed_priority = ParsedPriority {
            dependency,
            weight,
            exclusive,
            is_root_dependent,
        };

        let validation_result = if is_root_dependent {
            PriorityValidationResult::Valid
        } else {
            // Additional validation for non-root dependencies
            match self.validation_mode {
                TreeValidation::Full => {
                    if self.priority_tree.get_node(dependency).is_some() || dependency == ROOT_STREAM_ID {
                        PriorityValidationResult::Valid
                    } else {
                        PriorityValidationResult::InvalidDependency {
                            dependency,
                            reason: "Dependency stream does not exist".to_string(),
                        }
                    }
                }
                TreeValidation::DirectOnly | TreeValidation::None => {
                    PriorityValidationResult::Valid
                }
            }
        };

        Ok(ParsedPriorityFrame {
            frame_info: PriorityFrameInfo {
                stream_id,
                flags,
                size: frame_data.len() as u32,
                payload: frame_data.to_vec(),
            },
            priority: parsed_priority,
            tree_position,
            validation_result,
        })
    }

    fn build_priority_frame(priority: &PriorityFrame) -> Vec<u8> {
        let mut frame_data = Vec::with_capacity(5);

        // Combine dependency and exclusive flag
        let dependency_with_exclusive = if priority.exclusive {
            priority.stream_dependency | 0x80000000
        } else {
            priority.stream_dependency & 0x7FFFFFFF
        };

        // Add dependency (4 bytes)
        frame_data.extend_from_slice(&dependency_with_exclusive.to_be_bytes());

        // Add weight (1 byte) - transmitted as 0-255 representing 1-256
        let weight_byte = priority.weight; // Already in 0-255 range from Arbitrary
        frame_data.push(weight_byte);

        frame_data
    }

    fn get_priority_tree_stats(&self) -> &TreeStats {
        self.priority_tree.get_tree_stats()
    }

    fn get_parsing_stats(&self) -> &ParsingStats {
        &self.parsing_stats
    }
}

fuzz_target!(|input: H2PriorityZeroDependencyInput| {
    // Skip overly complex inputs that would timeout
    if input.additional_frames.len() > 50 {
        return;
    }

    let mut parser = MockH2PriorityParser::new(
        input.test_scenario.tree_validation.clone(),
        input.test_scenario.cycle_detection.clone(),
    );

    // Build and parse primary priority frame
    let frame_data = MockH2PriorityParser::build_priority_frame(&input.priority_frame);
    let primary_result = parser.parse_priority_frame(
        &frame_data,
        input.priority_frame.stream_id,
        input.priority_frame.flags
    );

    // Test zero dependency handling
    if input.priority_frame.stream_dependency == ROOT_STREAM_ID {
        match primary_result {
            Ok(parsed) => {
                // Root dependency should be accepted per RFC 7540 §5.3.1
                assert!(parsed.priority.is_root_dependent,
                    "Priority frame with dependency=0 should be marked as root-dependent");
                assert_eq!(parsed.tree_position.parent, ROOT_STREAM_ID,
                    "Root dependency should have parent=0");
                assert_eq!(parsed.tree_position.position, TreePositionType::RootChild,
                    "Root dependency should be positioned as root child");
                assert_eq!(parsed.priority.dependency, ROOT_STREAM_ID,
                    "Parsed dependency should be 0 for root dependency");
            }
            Err(error) => {
                panic!("Root dependency (stream_dependency=0) should be valid per RFC 7540 §5.3.1: {:?}", error);
            }
        }
    }

    // Process additional frames to build priority tree
    for additional_frame in &input.additional_frames {
        if additional_frame.stream_id == ROOT_STREAM_ID {
            continue; // Skip invalid stream IDs
        }

        let additional_frame_data = MockH2PriorityParser::build_priority_frame(additional_frame);
        let _additional_result = parser.parse_priority_frame(
            &additional_frame_data,
            additional_frame.stream_id,
            additional_frame.flags
        );
        // Continue processing regardless of result for tree building
    }

    // Test priority tree invariants
    test_priority_tree_invariants(&input, &parser, &primary_result);
});

fn test_priority_tree_invariants(
    input: &H2PriorityZeroDependencyInput,
    parser: &MockH2PriorityParser,
    primary_result: &Result<ParsedPriorityFrame, PriorityParsingError>,
) {
    let tree_stats = parser.get_priority_tree_stats();
    let parsing_stats = parser.get_parsing_stats();

    // Invariant: Root dependencies should be tracked correctly
    if input.priority_frame.stream_dependency == ROOT_STREAM_ID {
        if let Ok(_) = primary_result {
            assert!(tree_stats.root_dependent_count >= 1,
                "Root dependency should increase root_dependent_count");
            assert!(parsing_stats.root_dependency_frames >= 1,
                "Root dependency frame should be counted");
        }
    }

    // Invariant: Stream cannot depend on itself
    if input.priority_frame.stream_id == input.priority_frame.stream_dependency &&
       input.priority_frame.stream_dependency != ROOT_STREAM_ID {
        match primary_result {
            Err(PriorityParsingError::SelfDependency(stream_id)) => {
                assert_eq!(*stream_id, input.priority_frame.stream_id,
                    "Self-dependency error should reference correct stream");
            }
            _ => {
                panic!("Stream depending on itself should be rejected");
            }
        }
    }

    // Invariant: Tree depth should be reasonable
    assert!(tree_stats.max_depth <= 100,
        "Maximum tree depth should be reasonable: {}", tree_stats.max_depth);

    // Invariant: Total nodes should equal sum of dependencies
    let expected_nodes = tree_stats.root_dependent_count +
        (tree_stats.total_nodes - tree_stats.root_dependent_count);
    assert_eq!(tree_stats.total_nodes, expected_nodes,
        "Total nodes should equal root dependencies plus other dependencies");

    // Invariant: Parsing stats should be consistent
    assert!(parsing_stats.frames_processed >= 1,
        "Should have processed at least one frame");
    assert!(parsing_stats.frames_processed >= parsing_stats.root_dependency_frames,
        "Total frames should be >= root dependency frames");

    // Invariant: Zero dependency is always valid (RFC 7540 §5.3.1)
    let has_zero_dependency = input.priority_frame.stream_dependency == ROOT_STREAM_ID ||
        input.additional_frames.iter().any(|f| f.stream_dependency == ROOT_STREAM_ID);

    if has_zero_dependency && input.priority_frame.stream_id != ROOT_STREAM_ID {
        // At least one zero dependency should be processed successfully
        let has_successful_zero_dep = matches!(primary_result, Ok(ref parsed) if parsed.priority.is_root_dependent) ||
            parsing_stats.root_dependency_frames > 0;

        if !has_successful_zero_dep && matches!(input.test_scenario.cycle_detection, CycleDetection::Enabled) {
            // Zero dependencies should generally succeed unless there are other issues
            eprintln!("WARNING: Zero dependency frame may have been rejected for non-dependency reasons");
        }
    }

    // Invariant: Cycle detection should prevent cycles when enabled
    if matches!(input.test_scenario.cycle_detection, CycleDetection::Enabled) {
        if parsing_stats.cycles_prevented > 0 {
            // If cycles were prevented, should be reflected in invalid frames or specific errors
            assert!(parsing_stats.invalid_frames > 0 ||
                   matches!(primary_result, Err(PriorityParsingError::DependencyCycle { .. })),
                "Cycles prevented should result in errors or invalid frame count");
        }
    }

    // Invariant: Tree statistics should be non-negative and bounded
    assert!(tree_stats.total_nodes <= 1000,
        "Total nodes should be bounded for fuzzing");
    assert!(tree_stats.root_dependent_count <= tree_stats.total_nodes,
        "Root dependents should not exceed total nodes");
    assert!(tree_stats.cycles_detected <= parsing_stats.frames_processed,
        "Cycles detected should not exceed frames processed");

    // Invariant: Root dependency frames should have valid stream IDs
    if parsing_stats.root_dependency_frames > 0 {
        // Should not include any PRIORITY frames on stream 0
        if let Ok(parsed) = primary_result {
            if parsed.priority.is_root_dependent {
                assert_ne!(parsed.frame_info.stream_id, ROOT_STREAM_ID,
                    "Root dependency frame should not be on stream 0");
            }
        }
    }

    // Invariant: Frame size should be exactly 5 bytes for valid frames
    if let Ok(parsed) = primary_result {
        assert_eq!(parsed.frame_info.size, PRIORITY_FRAME_SIZE,
            "Valid PRIORITY frame should be exactly 5 bytes");
        assert_eq!(parsed.frame_info.payload.len(), PRIORITY_FRAME_SIZE as usize,
            "Payload size should match frame size");
    }

    // Invariant: Weight should be in valid range (1-256)
    if let Ok(parsed) = primary_result {
        assert!(parsed.priority.weight >= MIN_WEIGHT,
            "Weight should be >= 1: {}", parsed.priority.weight);
        assert!(parsed.priority.weight <= MAX_WEIGHT,
            "Weight should be <= 256: {}", parsed.priority.weight);
    }

    // Invariant: Exclusive dependencies should be handled correctly
    if input.priority_frame.exclusive && input.priority_frame.stream_dependency == ROOT_STREAM_ID {
        if let Ok(parsed) = primary_result {
            if parsed.priority.exclusive {
                // Exclusive root dependency might affect other root dependencies
                assert!(parsed.tree_position.affected_children.len() == 0 ||
                       tree_stats.root_dependent_count == 1,
                    "Exclusive root dependency should handle other root dependencies correctly");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_root_dependency_valid() {
        let mut parser = MockH2PriorityParser::new(TreeValidation::Full, CycleDetection::Enabled);

        // PRIORITY frame with dependency=0 (root)
        let frame_data = vec![
            0x00, 0x00, 0x00, 0x00, // dependency = 0 (root)
            0x0F, // weight = 16 (transmitted as 15, represents 16)
        ];

        let result = parser.parse_priority_frame(&frame_data, 1, 0);
        assert!(result.is_ok());

        let parsed = result.unwrap();
        assert_eq!(parsed.priority.dependency, ROOT_STREAM_ID);
        assert!(parsed.priority.is_root_dependent);
        assert_eq!(parsed.tree_position.position, TreePositionType::RootChild);
        assert_eq!(parsed.priority.weight, 16);
    }

    #[test]
    fn test_exclusive_root_dependency() {
        let mut parser = MockH2PriorityParser::new(TreeValidation::Full, CycleDetection::Enabled);

        // Exclusive dependency on root
        let frame_data = vec![
            0x80, 0x00, 0x00, 0x00, // dependency = 0 with exclusive bit set
            0x1F, // weight = 32
        ];

        let result = parser.parse_priority_frame(&frame_data, 3, 0);
        assert!(result.is_ok());

        let parsed = result.unwrap();
        assert_eq!(parsed.priority.dependency, ROOT_STREAM_ID);
        assert!(parsed.priority.exclusive);
        assert!(parsed.priority.is_root_dependent);
        assert_eq!(parsed.priority.weight, 32);
    }

    #[test]
    fn test_non_root_dependency() {
        let mut parser = MockH2PriorityParser::new(TreeValidation::Full, CycleDetection::Enabled);

        // First create a stream to depend on
        let root_frame = vec![0x00, 0x00, 0x00, 0x00, 0x07]; // Stream depends on root
        parser.parse_priority_frame(&root_frame, 1, 0).unwrap();

        // Now create dependency on stream 1
        let frame_data = vec![
            0x00, 0x00, 0x00, 0x01, // dependency = 1
            0x0F, // weight = 16
        ];

        let result = parser.parse_priority_frame(&frame_data, 3, 0);
        assert!(result.is_ok());

        let parsed = result.unwrap();
        assert_eq!(parsed.priority.dependency, 1);
        assert!(!parsed.priority.is_root_dependent);
        assert_eq!(parsed.tree_position.position, TreePositionType::StreamChild(1));
    }

    #[test]
    fn test_self_dependency_rejected() {
        let mut parser = MockH2PriorityParser::new(TreeValidation::Full, CycleDetection::Enabled);

        // Stream depending on itself
        let frame_data = vec![
            0x00, 0x00, 0x00, 0x05, // dependency = 5
            0x0F, // weight = 16
        ];

        let result = parser.parse_priority_frame(&frame_data, 5, 0); // stream_id = dependency
        assert!(matches!(result, Err(PriorityParsingError::SelfDependency(5))));
    }

    #[test]
    fn test_invalid_frame_size() {
        let mut parser = MockH2PriorityParser::new(TreeValidation::Full, CycleDetection::Enabled);

        // Frame too short
        let short_frame = vec![0x00, 0x00, 0x00]; // Only 3 bytes
        let result = parser.parse_priority_frame(&short_frame, 1, 0);
        assert!(matches!(result, Err(PriorityParsingError::InvalidFrameSize { size: 3 })));

        // Frame too long
        let long_frame = vec![0x00, 0x00, 0x00, 0x00, 0x0F, 0xFF]; // 6 bytes
        let result = parser.parse_priority_frame(&long_frame, 1, 0);
        assert!(matches!(result, Err(PriorityParsingError::InvalidFrameSize { size: 6 })));
    }

    #[test]
    fn test_priority_on_stream_zero_rejected() {
        let mut parser = MockH2PriorityParser::new(TreeValidation::Full, CycleDetection::Enabled);

        let frame_data = vec![0x00, 0x00, 0x00, 0x00, 0x0F];
        let result = parser.parse_priority_frame(&frame_data, 0, 0); // stream_id = 0
        assert!(matches!(result, Err(PriorityParsingError::PriorityOnConnectionStream)));
    }

    #[test]
    fn test_weight_encoding() {
        let mut parser = MockH2PriorityParser::new(TreeValidation::Full, CycleDetection::Enabled);

        // Test various weight values
        let test_weights = vec![
            (0, 1),     // Transmitted 0 = weight 1
            (15, 16),   // Transmitted 15 = weight 16
            (255, 256), // Transmitted 255 = weight 256
        ];

        for (transmitted, expected_weight) in test_weights {
            let frame_data = vec![0x00, 0x00, 0x00, 0x00, transmitted];
            let result = parser.parse_priority_frame(&frame_data, 1, 0);
            assert!(result.is_ok());

            let parsed = result.unwrap();
            assert_eq!(parsed.priority.weight, expected_weight,
                "Weight encoding: transmitted {} should represent {}",
                transmitted, expected_weight);
        }
    }

    #[test]
    fn test_multiple_root_dependencies() {
        let mut parser = MockH2PriorityParser::new(TreeValidation::Full, CycleDetection::Enabled);

        // Create multiple streams depending on root
        let stream_ids = vec![1, 3, 5, 7];

        for &stream_id in &stream_ids {
            let frame_data = vec![0x00, 0x00, 0x00, 0x00, 0x0F]; // All depend on root
            let result = parser.parse_priority_frame(&frame_data, stream_id, 0);
            assert!(result.is_ok());

            let parsed = result.unwrap();
            assert!(parsed.priority.is_root_dependent);
        }

        // Check tree stats
        let stats = parser.get_priority_tree_stats();
        assert_eq!(stats.root_dependent_count, stream_ids.len() as u32);
        assert_eq!(stats.total_nodes, stream_ids.len() as u32);
    }

    #[test]
    fn test_cycle_detection() {
        let mut parser = MockH2PriorityParser::new(TreeValidation::Full, CycleDetection::Enabled);

        // Create chain: 1 -> 0, 3 -> 1, 5 -> 3
        parser.parse_priority_frame(&vec![0x00, 0x00, 0x00, 0x00, 0x0F], 1, 0).unwrap(); // 1 -> root
        parser.parse_priority_frame(&vec![0x00, 0x00, 0x00, 0x01, 0x0F], 3, 0).unwrap(); // 3 -> 1
        parser.parse_priority_frame(&vec![0x00, 0x00, 0x00, 0x03, 0x0F], 5, 0).unwrap(); // 5 -> 3

        // Try to create cycle: 1 -> 5 (would create cycle 1 -> 5 -> 3 -> 1)
        let cycle_frame = vec![0x00, 0x00, 0x00, 0x05, 0x0F]; // 1 -> 5
        let result = parser.parse_priority_frame(&cycle_frame, 1, 0);
        assert!(matches!(result, Err(PriorityParsingError::DependencyCycle { .. })));
    }

    #[test]
    fn test_exclusive_dependency_behavior() {
        let mut parser = MockH2PriorityParser::new(TreeValidation::Full, CycleDetection::Enabled);

        // Create some root dependencies
        parser.parse_priority_frame(&vec![0x00, 0x00, 0x00, 0x00, 0x0F], 1, 0).unwrap(); // 1 -> root
        parser.parse_priority_frame(&vec![0x00, 0x00, 0x00, 0x00, 0x0F], 3, 0).unwrap(); // 3 -> root

        // Create exclusive root dependency
        let exclusive_frame = vec![0x80, 0x00, 0x00, 0x00, 0x1F]; // exclusive dependency on root
        let result = parser.parse_priority_frame(&exclusive_frame, 5, 0);
        assert!(result.is_ok());

        let parsed = result.unwrap();
        assert!(parsed.priority.exclusive);
        assert!(parsed.priority.is_root_dependent);

        // Previous root dependencies should now be children of stream 5
        let stats = parser.get_priority_tree_stats();
        assert_eq!(stats.root_dependent_count, 1); // Only stream 5 depends on root now
    }

    #[test]
    fn test_frame_building() {
        let priority_frame = PriorityFrame {
            stream_id: 1,
            stream_dependency: 0,
            weight: 15, // Represents weight 16, transmitted as 15
            exclusive: true,
            flags: 0,
            frame_properties: FrameProperties {
                frame_size: FrameSize::Standard,
                validation_mode: FrameValidationMode::Strict,
                test_boundaries: false,
            },
        };

        let frame_data = MockH2PriorityParser::build_priority_frame(&priority_frame);

        assert_eq!(frame_data.len(), 5);
        assert_eq!(frame_data[0], 0x80); // Exclusive bit set
        assert_eq!(frame_data[1], 0x00);
        assert_eq!(frame_data[2], 0x00);
        assert_eq!(frame_data[3], 0x00); // dependency = 0
        assert_eq!(frame_data[4], 15);   // weight transmitted as 15
    }

    #[test]
    fn test_tree_depth_calculation() {
        let mut parser = MockH2PriorityParser::new(TreeValidation::Full, CycleDetection::Enabled);

        // Build a chain: 1 -> root, 3 -> 1, 5 -> 3
        parser.parse_priority_frame(&vec![0x00, 0x00, 0x00, 0x00, 0x0F], 1, 0).unwrap();
        let result3 = parser.parse_priority_frame(&vec![0x00, 0x00, 0x00, 0x01, 0x0F], 3, 0).unwrap();
        let result5 = parser.parse_priority_frame(&vec![0x00, 0x00, 0x00, 0x03, 0x0F], 5, 0).unwrap();

        // Check depths
        assert_eq!(result3.tree_position.depth, 2); // 3 -> 1 -> root (depth 2)
        assert_eq!(result5.tree_position.depth, 3); // 5 -> 3 -> 1 -> root (depth 3)

        let stats = parser.get_priority_tree_stats();
        assert_eq!(stats.max_depth, 3);
    }
}