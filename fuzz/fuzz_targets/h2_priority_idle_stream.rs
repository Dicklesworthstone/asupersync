//! Fuzzing target for HTTP/2 PRIORITY frame edge cases.
//!
//! Tests RFC 7540 compliance for PRIORITY frame handling in various edge cases:
//! 1. PRIORITY frame for stream-id higher than current peer-initiated maximum
//! 2. PRIORITY frame with dependency on itself (must be PROTOCOL_ERROR per RFC 7540 §5.3.1)
//! 3. PRIORITY frame with weight=0 (must be treated as weight=1)
//! 4. PRIORITY frame before stream creation (idle streams)
//! 5. PRIORITY frame for closed/reset streams
//! 6. Exclusive flag handling with dependency loops
//!
//! Vulnerability areas:
//! - Stream dependency cycles causing infinite loops in priority calculations
//! - Self-dependency not being detected as protocol error
//! - Weight=0 causing division-by-zero or invalid priority calculations
//! - Stream state corruption for idle/non-existent streams
//! - Memory exhaustion through excessive priority tree depth
//! - Exclusive flag not properly restructuring dependency tree

#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use std::collections::HashMap;

/// Mock HTTP/2 connection for testing PRIORITY frame edge cases.
#[derive(Debug, Clone)]
pub struct MockPriorityConnection {
    /// Maximum stream ID seen from client (odd) and server (even)
    pub max_client_stream_id: u32,
    pub max_server_stream_id: u32,
    /// Stream states for tracking creation and closure
    pub streams: HashMap<u32, StreamState>,
    /// Priority tree for dependency tracking
    pub priority_tree: PriorityTree,
    /// Violations detected during processing
    pub violations: Vec<PriorityViolation>,
    /// Configuration for limits
    pub config: PriorityConfig,
}

/// Stream lifecycle states
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StreamState {
    /// Stream has never been used (idle)
    Idle,
    /// Stream is active (HEADERS received/sent)
    Open,
    /// Stream has been half-closed
    HalfClosed,
    /// Stream has been fully closed
    Closed,
    /// Stream was reset with RST_STREAM
    Reset,
}

/// Priority dependency tree node
#[derive(Debug, Clone)]
pub struct PriorityNode {
    /// Stream ID this node represents
    pub stream_id: u32,
    /// Parent stream ID (dependency), or None for root
    pub parent: Option<u32>,
    /// Weight (1-256, stored as 1-based)
    pub weight: u8,
    /// Whether this dependency is exclusive
    pub exclusive: bool,
    /// Child stream IDs depending on this stream
    pub children: Vec<u32>,
}

/// Priority dependency tree
#[derive(Debug, Clone)]
pub struct PriorityTree {
    /// All nodes in the tree
    pub nodes: HashMap<u32, PriorityNode>,
    /// Root of the tree (stream 0)
    pub root_children: Vec<u32>,
}

/// Configuration for priority handling
#[derive(Debug, Clone)]
pub struct PriorityConfig {
    /// Maximum allowed dependency tree depth to prevent stack overflow
    pub max_tree_depth: u32,
    /// Maximum number of children per node to prevent memory exhaustion
    pub max_children_per_node: u32,
}

/// PRIORITY frame violations
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PriorityViolation {
    /// Stream depends on itself (RFC 7540 §5.3.1)
    SelfDependency { stream_id: u32 },
    /// PRIORITY for stream ID higher than max peer-initiated
    IdlePriorityAboveMax { stream_id: u32, max_allowed: u32 },
    /// Weight was 0 but should be treated as 1
    ZeroWeightNormalized { stream_id: u32 },
    /// Dependency cycle detected
    DependencyCycle {
        stream_id: u32,
        cycle_path: Vec<u32>,
    },
    /// Tree depth exceeded maximum
    TreeDepthExceeded {
        stream_id: u32,
        depth: u32,
        limit: u32,
    },
    /// Too many children for a single node
    TooManyChildren {
        parent_stream: u32,
        children_count: usize,
        limit: u32,
    },
}

/// PRIORITY frame structure
#[derive(Debug, Clone, Arbitrary)]
pub struct MockPriorityFrame {
    /// Stream ID this frame affects
    pub stream_id: u32,
    /// Stream ID this stream depends on
    pub dependency_stream_id: u32,
    /// Whether the dependency is exclusive
    pub exclusive: bool,
    /// Priority weight (0-255, where 0 should be treated as 1)
    pub weight: u8,
}

/// Test scenario for priority frame sequences
#[derive(Debug, Clone, Arbitrary)]
pub struct PriorityFrameScenario {
    /// Sequence of PRIORITY frames to test
    pub priority_frames: Vec<MockPriorityFrame>,
    /// Stream lifecycle events to interleave
    pub stream_events: Vec<StreamEvent>,
    /// Whether to test with client or server perspective
    pub is_server: bool,
    /// Maximum operations to prevent infinite loops
    pub max_operations: u16,
}

/// Stream lifecycle events for testing
#[derive(Debug, Clone, Arbitrary)]
pub struct StreamEvent {
    /// Stream ID affected
    pub stream_id: u32,
    /// Type of event
    pub event_type: StreamEventType,
}

/// Types of stream events
#[derive(Debug, Clone, Arbitrary)]
pub enum StreamEventType {
    /// HEADERS frame opens stream
    Open,
    /// DATA frame with END_STREAM closes stream
    Close,
    /// RST_STREAM frame resets stream
    Reset,
}

/// Results of processing a PRIORITY frame
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PriorityProcessingResult {
    /// Frame processed successfully
    Success,
    /// Protocol error detected (should send GOAWAY)
    ProtocolError,
    /// Warning condition (logged but connection continues)
    Warning,
    /// Tree restructure occurred due to exclusive flag
    TreeRestructured,
}

impl Default for PriorityConfig {
    fn default() -> Self {
        Self {
            max_tree_depth: 100,
            max_children_per_node: 1000,
        }
    }
}

impl MockPriorityConnection {
    pub fn new(config: PriorityConfig, is_server: bool) -> Self {
        let mut tree = PriorityTree {
            nodes: HashMap::new(),
            root_children: Vec::new(),
        };

        // Stream 0 is implicit root
        tree.nodes.insert(
            0,
            PriorityNode {
                stream_id: 0,
                parent: None,
                weight: 1,
                exclusive: false,
                children: Vec::new(),
            },
        );

        Self {
            max_client_stream_id: if is_server { 0 } else { 1 }, // Server sees no client streams yet
            max_server_stream_id: if is_server { 2 } else { 0 }, // Client sees no server streams yet
            streams: HashMap::new(),
            priority_tree: tree,
            violations: Vec::new(),
            config,
        }
    }

    /// Process a PRIORITY frame
    pub fn process_priority_frame(&mut self, frame: MockPriorityFrame) -> PriorityProcessingResult {
        // RFC 7540 §5.3.1: Stream cannot depend on itself
        if frame.stream_id == frame.dependency_stream_id {
            self.violations.push(PriorityViolation::SelfDependency {
                stream_id: frame.stream_id,
            });
            return PriorityProcessingResult::ProtocolError;
        }

        // Check if stream ID is beyond maximum peer-initiated
        let max_allowed = if frame.stream_id % 2 == 1 {
            // Odd stream ID (client-initiated)
            self.max_client_stream_id
        } else {
            // Even stream ID (server-initiated)
            self.max_server_stream_id
        };

        if frame.stream_id > max_allowed && frame.stream_id > max_allowed + 2 {
            self.violations
                .push(PriorityViolation::IdlePriorityAboveMax {
                    stream_id: frame.stream_id,
                    max_allowed,
                });
            // This is allowed but worth noting for testing
        }

        // Weight 0 must be treated as 1 (RFC 7540 §5.3.2)
        let effective_weight = if frame.weight == 0 {
            self.violations
                .push(PriorityViolation::ZeroWeightNormalized {
                    stream_id: frame.stream_id,
                });
            1
        } else {
            frame.weight
        };

        // Check for dependency cycles before making changes
        if self.would_create_cycle(frame.stream_id, frame.dependency_stream_id) {
            let cycle_path = self.find_cycle_path(frame.stream_id, frame.dependency_stream_id);
            self.violations.push(PriorityViolation::DependencyCycle {
                stream_id: frame.stream_id,
                cycle_path,
            });
            return PriorityProcessingResult::ProtocolError;
        }

        // Update or create the priority node
        let old_parent = self
            .priority_tree
            .nodes
            .get(&frame.stream_id)
            .and_then(|node| node.parent);

        // Remove from old parent's children
        if let Some(old_parent_id) = old_parent {
            if let Some(old_parent_node) = self.priority_tree.nodes.get_mut(&old_parent_id) {
                old_parent_node
                    .children
                    .retain(|&child| child != frame.stream_id);
            } else if old_parent_id == 0 {
                self.priority_tree
                    .root_children
                    .retain(|&child| child != frame.stream_id);
            }
        }

        // Handle exclusive dependency
        let mut tree_restructured = false;
        if frame.exclusive {
            // Make all existing children of dependency become children of this stream
            let existing_children = if frame.dependency_stream_id == 0 {
                self.priority_tree.root_children.clone()
            } else {
                self.priority_tree
                    .nodes
                    .get(&frame.dependency_stream_id)
                    .map(|node| node.children.clone())
                    .unwrap_or_default()
            };

            // Move existing children to be children of the new stream
            for child_id in &existing_children {
                if let Some(child_node) = self.priority_tree.nodes.get_mut(child_id) {
                    child_node.parent = Some(frame.stream_id);
                }
            }

            // Clear old parent's children
            if frame.dependency_stream_id == 0 {
                self.priority_tree.root_children.clear();
            } else if let Some(parent_node) = self
                .priority_tree
                .nodes
                .get_mut(&frame.dependency_stream_id)
            {
                parent_node.children.clear();
            }

            // Set exclusive stream as only child of dependency
            if frame.dependency_stream_id == 0 {
                self.priority_tree.root_children.push(frame.stream_id);
            } else {
                if let Some(parent_node) = self
                    .priority_tree
                    .nodes
                    .get_mut(&frame.dependency_stream_id)
                {
                    parent_node.children.push(frame.stream_id);
                    // Check children limit
                    if parent_node.children.len() > self.config.max_children_per_node as usize {
                        self.violations.push(PriorityViolation::TooManyChildren {
                            parent_stream: frame.dependency_stream_id,
                            children_count: parent_node.children.len(),
                            limit: self.config.max_children_per_node,
                        });
                    }
                }
            }

            // Update the stream's node
            self.priority_tree.nodes.insert(
                frame.stream_id,
                PriorityNode {
                    stream_id: frame.stream_id,
                    parent: if frame.dependency_stream_id == 0 {
                        None
                    } else {
                        Some(frame.dependency_stream_id)
                    },
                    weight: effective_weight,
                    exclusive: frame.exclusive,
                    children: existing_children,
                },
            );

            tree_restructured = true;
        } else {
            // Non-exclusive: just add as another child
            if frame.dependency_stream_id == 0 {
                self.priority_tree.root_children.push(frame.stream_id);
            } else {
                // Ensure dependency parent exists
                if !self
                    .priority_tree
                    .nodes
                    .contains_key(&frame.dependency_stream_id)
                {
                    self.priority_tree.nodes.insert(
                        frame.dependency_stream_id,
                        PriorityNode {
                            stream_id: frame.dependency_stream_id,
                            parent: None, // Will be root child
                            weight: 16,   // Default weight
                            exclusive: false,
                            children: Vec::new(),
                        },
                    );
                    self.priority_tree
                        .root_children
                        .push(frame.dependency_stream_id);
                }

                if let Some(parent_node) = self
                    .priority_tree
                    .nodes
                    .get_mut(&frame.dependency_stream_id)
                {
                    if !parent_node.children.contains(&frame.stream_id) {
                        parent_node.children.push(frame.stream_id);
                    }
                    // Check children limit
                    if parent_node.children.len() > self.config.max_children_per_node as usize {
                        self.violations.push(PriorityViolation::TooManyChildren {
                            parent_stream: frame.dependency_stream_id,
                            children_count: parent_node.children.len(),
                            limit: self.config.max_children_per_node,
                        });
                    }
                }
            }

            self.priority_tree.nodes.insert(
                frame.stream_id,
                PriorityNode {
                    stream_id: frame.stream_id,
                    parent: if frame.dependency_stream_id == 0 {
                        None
                    } else {
                        Some(frame.dependency_stream_id)
                    },
                    weight: effective_weight,
                    exclusive: frame.exclusive,
                    children: self
                        .priority_tree
                        .nodes
                        .get(&frame.stream_id)
                        .map(|node| node.children.clone())
                        .unwrap_or_default(),
                },
            );
        }

        // Check tree depth
        let depth = self.calculate_stream_depth(frame.stream_id);
        if depth > self.config.max_tree_depth {
            self.violations.push(PriorityViolation::TreeDepthExceeded {
                stream_id: frame.stream_id,
                depth,
                limit: self.config.max_tree_depth,
            });
            return PriorityProcessingResult::Warning;
        }

        if tree_restructured {
            PriorityProcessingResult::TreeRestructured
        } else {
            PriorityProcessingResult::Success
        }
    }

    /// Process a stream lifecycle event
    pub fn process_stream_event(&mut self, event: StreamEvent) {
        match event.event_type {
            StreamEventType::Open => {
                // Update max stream ID if this is higher
                if event.stream_id % 2 == 1 {
                    // Client-initiated (odd)
                    self.max_client_stream_id = self.max_client_stream_id.max(event.stream_id);
                } else {
                    // Server-initiated (even)
                    self.max_server_stream_id = self.max_server_stream_id.max(event.stream_id);
                }
                self.streams.insert(event.stream_id, StreamState::Open);
            }
            StreamEventType::Close => {
                self.streams.insert(event.stream_id, StreamState::Closed);
            }
            StreamEventType::Reset => {
                self.streams.insert(event.stream_id, StreamState::Reset);
            }
        }
    }

    /// Check if creating a dependency would form a cycle
    fn would_create_cycle(&self, stream_id: u32, dependency_id: u32) -> bool {
        if dependency_id == 0 {
            return false; // Root dependency can't create cycle
        }

        // Walk up from dependency to see if we reach stream_id
        let mut current = dependency_id;
        let mut visited = std::collections::HashSet::new();

        while current != 0 {
            if current == stream_id {
                return true; // Cycle detected
            }
            if visited.contains(&current) {
                return false; // Already checked this path
            }
            visited.insert(current);

            current = self
                .priority_tree
                .nodes
                .get(&current)
                .and_then(|node| node.parent)
                .unwrap_or(0);
        }

        false
    }

    /// Find the path of a dependency cycle for reporting
    fn find_cycle_path(&self, stream_id: u32, dependency_id: u32) -> Vec<u32> {
        let mut path = vec![stream_id, dependency_id];
        let mut current = dependency_id;

        while current != 0 && current != stream_id {
            current = self
                .priority_tree
                .nodes
                .get(&current)
                .and_then(|node| node.parent)
                .unwrap_or(0);

            if current == stream_id {
                path.push(current);
                break;
            }
            if current != 0 {
                path.push(current);
            }
        }

        path
    }

    /// Calculate depth of a stream in the priority tree
    fn calculate_stream_depth(&self, stream_id: u32) -> u32 {
        let mut depth = 0;
        let mut current = stream_id;

        while current != 0 {
            current = self
                .priority_tree
                .nodes
                .get(&current)
                .and_then(|node| node.parent)
                .unwrap_or(0);
            depth += 1;

            if depth > 1000 {
                return depth; // Prevent infinite loop
            }
        }

        depth
    }

    /// Get all violations detected
    pub fn violations(&self) -> &[PriorityViolation] {
        &self.violations
    }

    /// Get current priority tree state for analysis
    pub fn tree_stats(&self) -> TreeStats {
        TreeStats {
            node_count: self.priority_tree.nodes.len(),
            max_depth: self
                .priority_tree
                .nodes
                .keys()
                .map(|&stream_id| self.calculate_stream_depth(stream_id))
                .max()
                .unwrap_or(0),
            max_children: self
                .priority_tree
                .nodes
                .values()
                .map(|node| node.children.len())
                .max()
                .unwrap_or(0),
            root_children_count: self.priority_tree.root_children.len(),
        }
    }
}

/// Statistics about the priority tree
#[derive(Debug, Clone)]
pub struct TreeStats {
    pub node_count: usize,
    pub max_depth: u32,
    pub max_children: usize,
    pub root_children_count: usize,
}

/// Test basic self-dependency detection
fn test_self_dependency_detection() {
    let mut conn = MockPriorityConnection::new(PriorityConfig::default(), false);

    let self_dep_frame = MockPriorityFrame {
        stream_id: 5,
        dependency_stream_id: 5, // Self-dependency!
        exclusive: false,
        weight: 16,
    };

    let result = conn.process_priority_frame(self_dep_frame);
    assert_eq!(result, PriorityProcessingResult::ProtocolError);

    let violations = conn.violations();
    assert_eq!(violations.len(), 1);
    assert!(matches!(
        violations[0],
        PriorityViolation::SelfDependency { stream_id: 5 }
    ));
}

/// Test weight=0 normalization
fn test_zero_weight_normalization() {
    let mut conn = MockPriorityConnection::new(PriorityConfig::default(), false);

    let zero_weight_frame = MockPriorityFrame {
        stream_id: 3,
        dependency_stream_id: 0,
        exclusive: false,
        weight: 0, // Should be treated as 1
    };

    let result = conn.process_priority_frame(zero_weight_frame);
    assert_eq!(result, PriorityProcessingResult::Success);

    let violations = conn.violations();
    assert_eq!(violations.len(), 1);
    assert!(matches!(
        violations[0],
        PriorityViolation::ZeroWeightNormalized { stream_id: 3 }
    ));

    // Verify the weight was actually normalized
    let node = conn.priority_tree.nodes.get(&3).unwrap();
    assert_eq!(node.weight, 1);
}

/// Test idle stream priority beyond maximum
fn test_idle_stream_priority() {
    let mut conn = MockPriorityConnection::new(PriorityConfig::default(), false);

    // Current max client stream ID is 1 (from constructor)
    let idle_priority_frame = MockPriorityFrame {
        stream_id: 101, // Way beyond current max (1)
        dependency_stream_id: 0,
        exclusive: false,
        weight: 16,
    };

    let result = conn.process_priority_frame(idle_priority_frame);
    assert_eq!(result, PriorityProcessingResult::Success);

    let violations = conn.violations();
    assert_eq!(violations.len(), 1);
    assert!(matches!(
        violations[0],
        PriorityViolation::IdlePriorityAboveMax {
            stream_id: 101,
            max_allowed: 1
        }
    ));
}

/// Test dependency cycle detection
fn test_dependency_cycle_detection() {
    let mut conn = MockPriorityConnection::new(PriorityConfig::default(), false);

    // Create: 1 depends on 3
    let frame1 = MockPriorityFrame {
        stream_id: 1,
        dependency_stream_id: 3,
        exclusive: false,
        weight: 16,
    };
    conn.process_priority_frame(frame1);

    // Create: 3 depends on 5
    let frame2 = MockPriorityFrame {
        stream_id: 3,
        dependency_stream_id: 5,
        exclusive: false,
        weight: 16,
    };
    conn.process_priority_frame(frame2);

    // Try to create cycle: 5 depends on 1 (would create 1->3->5->1)
    let cycle_frame = MockPriorityFrame {
        stream_id: 5,
        dependency_stream_id: 1,
        exclusive: false,
        weight: 16,
    };

    let result = conn.process_priority_frame(cycle_frame);
    assert_eq!(result, PriorityProcessingResult::ProtocolError);

    let violations = conn.violations();
    // Should find the cycle violation
    assert!(
        violations
            .iter()
            .any(|v| matches!(v, PriorityViolation::DependencyCycle { .. }))
    );
}

/// Test exclusive dependency tree restructuring
fn test_exclusive_dependency() {
    let mut conn = MockPriorityConnection::new(PriorityConfig::default(), false);

    // Set up: 1 and 3 both depend on root (0)
    let frame1 = MockPriorityFrame {
        stream_id: 1,
        dependency_stream_id: 0,
        exclusive: false,
        weight: 16,
    };
    conn.process_priority_frame(frame1);

    let frame2 = MockPriorityFrame {
        stream_id: 3,
        dependency_stream_id: 0,
        exclusive: false,
        weight: 16,
    };
    conn.process_priority_frame(frame2);

    // Now 5 depends exclusively on root - should make 1 and 3 children of 5
    let exclusive_frame = MockPriorityFrame {
        stream_id: 5,
        dependency_stream_id: 0,
        exclusive: true,
        weight: 16,
    };

    let result = conn.process_priority_frame(exclusive_frame);
    assert_eq!(result, PriorityProcessingResult::TreeRestructured);

    // Check tree structure: root should only have 5 as child
    assert_eq!(conn.priority_tree.root_children, vec![5]);

    // 5 should have 1 and 3 as children
    let node5 = conn.priority_tree.nodes.get(&5).unwrap();
    assert_eq!(node5.children.len(), 2);
    assert!(node5.children.contains(&1));
    assert!(node5.children.contains(&3));

    // 1 and 3 should now depend on 5
    let node1 = conn.priority_tree.nodes.get(&1).unwrap();
    assert_eq!(node1.parent, Some(5));

    let node3 = conn.priority_tree.nodes.get(&3).unwrap();
    assert_eq!(node3.parent, Some(5));
}

fuzz_target!(|scenario: PriorityFrameScenario| {
    // Limit operations to prevent timeouts
    let max_ops = scenario.max_operations.min(1000);
    let limited_frames: Vec<MockPriorityFrame> = scenario
        .priority_frames
        .into_iter()
        .take(max_ops as usize)
        .collect();
    let limited_events: Vec<StreamEvent> = scenario
        .stream_events
        .into_iter()
        .take(max_ops as usize)
        .collect();

    if limited_frames.is_empty() && limited_events.is_empty() {
        return;
    }

    let mut config = PriorityConfig::default();
    // Use smaller limits for fuzzing to catch issues faster
    config.max_tree_depth = 50;
    config.max_children_per_node = 100;

    let mut conn = MockPriorityConnection::new(config, scenario.is_server);

    // Track all violations found during the test
    let mut protocol_errors = 0;
    let mut warnings = 0;

    // Interleave stream events and priority frames for realistic testing
    let mut event_idx = 0;
    let mut frame_idx = 0;

    for i in 0..max_ops {
        // Alternate between events and frames, or process what's available
        if i % 2 == 0 && event_idx < limited_events.len() {
            conn.process_stream_event(limited_events[event_idx].clone());
            event_idx += 1;
        } else if frame_idx < limited_frames.len() {
            let result = conn.process_priority_frame(limited_frames[frame_idx].clone());
            match result {
                PriorityProcessingResult::ProtocolError => protocol_errors += 1,
                PriorityProcessingResult::Warning => warnings += 1,
                _ => {}
            }
            frame_idx += 1;
        } else {
            break;
        }
    }

    // Verify tree consistency at the end
    let stats = conn.tree_stats();
    assert!(
        stats.node_count <= 2000,
        "Tree grew too large: {} nodes",
        stats.node_count
    );
    assert!(
        stats.max_depth <= 100,
        "Tree too deep: {} levels",
        stats.max_depth
    );

    // Verify no self-dependencies exist in final tree
    for (stream_id, node) in &conn.priority_tree.nodes {
        if let Some(parent) = node.parent {
            assert_ne!(
                *stream_id, parent,
                "Self-dependency found: stream {} depends on itself",
                stream_id
            );
        }
    }

    // Test specific edge cases periodically
    if limited_frames.len() == 1 {
        test_self_dependency_detection();
        test_zero_weight_normalization();
        test_idle_stream_priority();
        test_dependency_cycle_detection();
        test_exclusive_dependency();
    }

    // Ensure all weights are >= 1
    for node in conn.priority_tree.nodes.values() {
        assert!(
            node.weight >= 1,
            "Weight below minimum: stream {} has weight {}",
            node.stream_id,
            node.weight
        );
        assert!(
            node.weight <= 256,
            "Weight above maximum: stream {} has weight {}",
            node.stream_id,
            node.weight
        );
    }
});
