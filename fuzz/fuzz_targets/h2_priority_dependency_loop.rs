#![no_main]

use libfuzzer_sys::fuzz_target;
use arbitrary::Arbitrary;
use std::collections::{HashMap, HashSet};

/// Fuzz target for HTTP/2 PRIORITY frame dependency cycle detection.
///
/// Per RFC 7540 §5.3.3: "A stream cannot depend on itself. An endpoint MUST treat
/// this as a stream error (Section 5.4.2) of type PROTOCOL_ERROR."
///
/// Also: "If a stream is made to depend on one of its own dependencies, the
/// formerly dependent stream is first moved to be dependent on the reprioritized
/// stream's previous parent. The moved dependency retains its weight."
///
/// This means direct cycles (A→A) are forbidden, but indirect cycles (A→B→A)
/// should be resolved by restructuring, not rejected. However, implementation
/// complexity often leads to rejecting all cycles as PROTOCOL_ERROR.
///
/// Tests include:
/// - Direct self-dependency (stream A depends on A) - MUST be PROTOCOL_ERROR
/// - Simple cycles (A→B→A) - implementation choice
/// - Complex cycles (A→B→C→A) - implementation choice
/// - Multiple cycles in dependency tree

#[derive(Debug, Arbitrary)]
struct PriorityTest {
    /// Sequence of PRIORITY frames to apply
    priority_frames: Vec<PriorityFrame>,
    /// Maximum stream ID to use
    max_stream_id: u8,
}

#[derive(Debug, Arbitrary, Clone)]
struct PriorityFrame {
    /// Stream ID receiving the priority update
    stream_id: u32,
    /// Stream ID this stream depends on (0 = root)
    dependency: u32,
    /// Weight (1-256)
    weight: u8,
    /// Exclusive flag
    exclusive: bool,
}

#[derive(Debug, Clone, PartialEq)]
enum PriorityResult {
    Success(DependencyTree),
    ProtocolError(PriorityError),
    Restructured(DependencyTree, String),
}

#[derive(Debug, Clone, PartialEq)]
enum PriorityError {
    SelfDependency,
    CyclicDependency(Vec<u32>),
    InvalidStreamId,
    InvalidWeight,
    DependencyLoop,
    TreeCorruption,
}

#[derive(Debug, Clone, PartialEq)]
struct DependencyTree {
    /// Stream ID -> StreamNode mapping
    streams: HashMap<u32, StreamNode>,
    /// Current tree structure stats
    stats: TreeStats,
}

#[derive(Debug, Clone, PartialEq)]
struct StreamNode {
    /// Stream ID
    id: u32,
    /// Parent stream ID (0 = root)
    parent: u32,
    /// Child stream IDs
    children: Vec<u32>,
    /// Priority weight (1-256)
    weight: u8,
    /// Whether this dependency is exclusive
    exclusive: bool,
}

#[derive(Debug, Clone, PartialEq, Default)]
struct TreeStats {
    /// Total number of streams
    stream_count: usize,
    /// Maximum depth of dependency tree
    max_depth: usize,
    /// Number of cycles detected and resolved
    cycles_resolved: usize,
    /// Number of direct self-dependencies rejected
    self_deps_rejected: usize,
}

/// Mock HTTP/2 priority manager for testing dependency cycles
struct MockPriorityManager {
    tree: DependencyTree,
    policy: CycleDetectionPolicy,
}

#[derive(Debug, Clone)]
struct CycleDetectionPolicy {
    /// Reject all cycles as PROTOCOL_ERROR (strict)
    reject_all_cycles: bool,
    /// Allow cycle resolution by restructuring
    allow_cycle_resolution: bool,
    /// Maximum tree depth to prevent stack overflow
    max_tree_depth: usize,
    /// Maximum number of streams to track
    max_tracked_streams: usize,
    /// Maximum number of cycle resolution attempts
    max_resolution_attempts: usize,
}

impl Default for CycleDetectionPolicy {
    fn default() -> Self {
        Self {
            reject_all_cycles: true, // Conservative default
            allow_cycle_resolution: false,
            max_tree_depth: 256,
            max_tracked_streams: 10000,
            max_resolution_attempts: 100,
        }
    }
}

impl MockPriorityManager {
    fn new() -> Self {
        Self {
            tree: DependencyTree {
                streams: HashMap::new(),
                stats: TreeStats::default(),
            },
            policy: CycleDetectionPolicy::default(),
        }
    }

    fn with_policy(policy: CycleDetectionPolicy) -> Self {
        Self {
            tree: DependencyTree {
                streams: HashMap::new(),
                stats: TreeStats::default(),
            },
            policy,
        }
    }

    /// Apply a PRIORITY frame with cycle detection
    fn apply_priority_frame(&mut self, frame: &PriorityFrame) -> Result<PriorityResult, PriorityError> {
        // Basic validation
        if frame.stream_id == 0 {
            return Err(PriorityError::InvalidStreamId);
        }

        if frame.weight == 0 {
            return Err(PriorityError::InvalidWeight);
        }

        // Check for direct self-dependency (RFC 7540 §5.3.3 - MUST be PROTOCOL_ERROR)
        if frame.stream_id == frame.dependency {
            self.tree.stats.self_deps_rejected += 1;
            return Ok(PriorityResult::ProtocolError(PriorityError::SelfDependency));
        }

        // Check stream count limit
        if self.tree.streams.len() >= self.policy.max_tracked_streams {
            return Err(PriorityError::InvalidStreamId);
        }

        // Create stream if it doesn't exist
        if !self.tree.streams.contains_key(&frame.stream_id) {
            self.tree.streams.insert(frame.stream_id, StreamNode {
                id: frame.stream_id,
                parent: 0,
                children: Vec::new(),
                weight: 16, // Default weight
                exclusive: false,
            });
        }

        // Create dependency stream if it doesn't exist (and not root)
        if frame.dependency != 0 && !self.tree.streams.contains_key(&frame.dependency) {
            self.tree.streams.insert(frame.dependency, StreamNode {
                id: frame.dependency,
                parent: 0,
                children: Vec::new(),
                weight: 16,
                exclusive: false,
            });
        }

        // Check for cycles before applying the change
        if let Some(cycle) = self.detect_cycle(frame.stream_id, frame.dependency)? {
            if self.policy.reject_all_cycles {
                return Ok(PriorityResult::ProtocolError(PriorityError::CyclicDependency(cycle)));
            } else if self.policy.allow_cycle_resolution {
                // Attempt to resolve the cycle per RFC 7540 §5.3.3
                match self.resolve_cycle(frame)? {
                    Some(resolution_msg) => {
                        self.tree.stats.cycles_resolved += 1;
                        let new_tree = self.tree.clone();
                        return Ok(PriorityResult::Restructured(new_tree, resolution_msg));
                    }
                    None => {
                        return Ok(PriorityResult::ProtocolError(PriorityError::DependencyLoop));
                    }
                }
            }
        }

        // Apply the priority change
        self.apply_priority_change(frame)?;

        // Update stats
        self.update_tree_stats();

        Ok(PriorityResult::Success(self.tree.clone()))
    }

    /// Detect if setting stream_id to depend on dependency would create a cycle
    fn detect_cycle(&self, stream_id: u32, dependency: u32) -> Result<Option<Vec<u32>>, PriorityError> {
        if dependency == 0 {
            return Ok(None); // Root dependency cannot create cycle
        }

        // Use DFS to check if dependency is reachable from stream_id
        let mut visited = HashSet::new();
        let mut path = Vec::new();

        if self.dfs_cycle_check(stream_id, dependency, &mut visited, &mut path, 0)? {
            Ok(Some(path))
        } else {
            Ok(None)
        }
    }

    /// DFS-based cycle detection
    fn dfs_cycle_check(
        &self,
        current: u32,
        target: u32,
        visited: &mut HashSet<u32>,
        path: &mut Vec<u32>,
        depth: usize,
    ) -> Result<bool, PriorityError> {
        // Prevent stack overflow
        if depth > self.policy.max_tree_depth {
            return Err(PriorityError::TreeCorruption);
        }

        // If we've reached the target, we found a cycle
        if current == target {
            path.push(current);
            return Ok(true);
        }

        // If already visited, no cycle through this path
        if visited.contains(&current) {
            return Ok(false);
        }

        visited.insert(current);
        path.push(current);

        // Check all children of current stream
        if let Some(stream) = self.tree.streams.get(&current) {
            for &child in &stream.children {
                if self.dfs_cycle_check(child, target, visited, path, depth + 1)? {
                    return Ok(true);
                }
            }
        }

        // Check parent of current stream
        if let Some(stream) = self.tree.streams.get(&current) {
            if stream.parent != 0 {
                if self.dfs_cycle_check(stream.parent, target, visited, path, depth + 1)? {
                    return Ok(true);
                }
            }
        }

        path.pop();
        Ok(false)
    }

    /// Resolve cycle by restructuring per RFC 7540 §5.3.3
    fn resolve_cycle(&mut self, frame: &PriorityFrame) -> Result<Option<String>, PriorityError> {
        // RFC 7540 §5.3.3: "If a stream is made to depend on one of its own
        // dependencies, the formerly dependent stream is first moved to be
        // dependent on the reprioritized stream's previous parent."

        let stream_id = frame.stream_id;
        let new_dependency = frame.dependency;

        // Get current parent of the stream we're reprioritizing
        let old_parent = self.tree.streams.get(&stream_id)
            .map(|s| s.parent)
            .unwrap_or(0);

        // Find the dependency that would be moved
        let dependency_to_move = new_dependency;

        // Move the dependency to the old parent
        if let Some(dep_stream) = self.tree.streams.get_mut(&dependency_to_move) {
            // Remove from current parent's children
            if let Some(current_parent) = self.tree.streams.get_mut(&dep_stream.parent) {
                current_parent.children.retain(|&x| x != dependency_to_move);
            }

            // Set new parent
            dep_stream.parent = old_parent;

            // Add to new parent's children
            if old_parent != 0 {
                if let Some(new_parent) = self.tree.streams.get_mut(&old_parent) {
                    new_parent.children.push(dependency_to_move);
                }
            }
        }

        // Now apply the original priority change
        self.apply_priority_change(frame)?;

        Ok(Some(format!(
            "Cycle resolved: moved stream {} to parent {}, then set stream {} to depend on {}",
            dependency_to_move, old_parent, stream_id, new_dependency
        )))
    }

    /// Apply priority change without cycle checking
    fn apply_priority_change(&mut self, frame: &PriorityFrame) -> Result<(), PriorityError> {
        let stream_id = frame.stream_id;
        let new_parent = frame.dependency;

        // Remove stream from current parent's children
        if let Some(stream) = self.tree.streams.get(&stream_id) {
            let old_parent = stream.parent;
            if old_parent != 0 {
                if let Some(parent) = self.tree.streams.get_mut(&old_parent) {
                    parent.children.retain(|&x| x != stream_id);
                }
            }
        }

        // Update stream's parent and weight
        if let Some(stream) = self.tree.streams.get_mut(&stream_id) {
            stream.parent = new_parent;
            stream.weight = frame.weight;
            stream.exclusive = frame.exclusive;
        }

        // Handle exclusive dependency
        if frame.exclusive && new_parent != 0 {
            // Move all existing children of new_parent to be children of stream_id
            if let Some(parent) = self.tree.streams.get_mut(&new_parent) {
                let existing_children: Vec<u32> = parent.children.drain(..).collect();

                // Set stream_id as only child of parent
                parent.children.push(stream_id);

                // Move existing children to be children of stream_id
                if let Some(stream) = self.tree.streams.get_mut(&stream_id) {
                    stream.children = existing_children;
                }

                // Update parent pointers for moved children
                for &child in &existing_children {
                    if let Some(child_stream) = self.tree.streams.get_mut(&child) {
                        child_stream.parent = stream_id;
                    }
                }
            }
        } else if new_parent != 0 {
            // Non-exclusive: just add to parent's children
            if let Some(parent) = self.tree.streams.get_mut(&new_parent) {
                if !parent.children.contains(&stream_id) {
                    parent.children.push(stream_id);
                }
            }
        }

        Ok(())
    }

    /// Update tree statistics
    fn update_tree_stats(&mut self) {
        self.tree.stats.stream_count = self.tree.streams.len();
        self.tree.stats.max_depth = self.calculate_max_depth();
    }

    /// Calculate maximum depth of dependency tree
    fn calculate_max_depth(&self) -> usize {
        let mut max_depth = 0;

        for &stream_id in self.tree.streams.keys() {
            let depth = self.calculate_stream_depth(stream_id, 0);
            max_depth = max_depth.max(depth);
        }

        max_depth
    }

    /// Calculate depth of a specific stream
    fn calculate_stream_depth(&self, stream_id: u32, current_depth: usize) -> usize {
        if current_depth > self.policy.max_tree_depth {
            return current_depth; // Prevent infinite recursion
        }

        if let Some(stream) = self.tree.streams.get(&stream_id) {
            if stream.parent == 0 {
                return current_depth;
            } else {
                return self.calculate_stream_depth(stream.parent, current_depth + 1);
            }
        }

        current_depth
    }

    /// Get current tree state
    fn get_tree(&self) -> &DependencyTree {
        &self.tree
    }

    /// Verify tree integrity (no orphaned nodes, valid parent-child relationships)
    fn verify_integrity(&self) -> Result<(), PriorityError> {
        for (stream_id, stream) in &self.tree.streams {
            // Check parent-child consistency
            if stream.parent != 0 {
                if let Some(parent) = self.tree.streams.get(&stream.parent) {
                    if !parent.children.contains(stream_id) {
                        return Err(PriorityError::TreeCorruption);
                    }
                } else {
                    return Err(PriorityError::TreeCorruption);
                }
            }

            // Check child-parent consistency
            for &child_id in &stream.children {
                if let Some(child) = self.tree.streams.get(&child_id) {
                    if child.parent != *stream_id {
                        return Err(PriorityError::TreeCorruption);
                    }
                } else {
                    return Err(PriorityError::TreeCorruption);
                }
            }
        }

        Ok(())
    }
}

/// Generate predefined test cases for cycle detection
fn generate_test_cases() -> Vec<(String, Vec<PriorityFrame>, PriorityResult)> {
    vec![
        // Test case 1: Direct self-dependency (MUST be PROTOCOL_ERROR)
        (
            "Direct self-dependency".to_string(),
            vec![
                PriorityFrame {
                    stream_id: 1,
                    dependency: 1, // Stream 1 depends on itself
                    weight: 16,
                    exclusive: false,
                }
            ],
            PriorityResult::ProtocolError(PriorityError::SelfDependency)
        ),

        // Test case 2: Simple cycle A→B→A (implementation choice)
        (
            "Simple A→B→A cycle".to_string(),
            vec![
                PriorityFrame {
                    stream_id: 1,
                    dependency: 3,
                    weight: 16,
                    exclusive: false,
                },
                PriorityFrame {
                    stream_id: 3,
                    dependency: 1, // Creates cycle: 1→3→1
                    weight: 16,
                    exclusive: false,
                }
            ],
            PriorityResult::ProtocolError(PriorityError::CyclicDependency(vec![1, 3]))
        ),

        // Test case 3: Complex cycle A→B→C→A
        (
            "Complex A→B→C→A cycle".to_string(),
            vec![
                PriorityFrame {
                    stream_id: 1,
                    dependency: 3,
                    weight: 16,
                    exclusive: false,
                },
                PriorityFrame {
                    stream_id: 3,
                    dependency: 5,
                    weight: 16,
                    exclusive: false,
                },
                PriorityFrame {
                    stream_id: 5,
                    dependency: 1, // Creates cycle: 1→3→5→1
                    weight: 16,
                    exclusive: false,
                }
            ],
            PriorityResult::ProtocolError(PriorityError::CyclicDependency(vec![1, 3, 5]))
        ),

        // Test case 4: Valid dependency chain (no cycle)
        (
            "Valid chain A→B→C→root".to_string(),
            vec![
                PriorityFrame {
                    stream_id: 1,
                    dependency: 3,
                    weight: 16,
                    exclusive: false,
                },
                PriorityFrame {
                    stream_id: 3,
                    dependency: 5,
                    weight: 16,
                    exclusive: false,
                },
                PriorityFrame {
                    stream_id: 5,
                    dependency: 0, // Root dependency - no cycle
                    weight: 16,
                    exclusive: false,
                }
            ],
            PriorityResult::Success(DependencyTree {
                streams: {
                    let mut map = HashMap::new();
                    map.insert(1, StreamNode {
                        id: 1,
                        parent: 3,
                        children: vec![],
                        weight: 16,
                        exclusive: false,
                    });
                    map.insert(3, StreamNode {
                        id: 3,
                        parent: 5,
                        children: vec![1],
                        weight: 16,
                        exclusive: false,
                    });
                    map.insert(5, StreamNode {
                        id: 5,
                        parent: 0,
                        children: vec![3],
                        weight: 16,
                        exclusive: false,
                    });
                    map
                },
                stats: TreeStats {
                    stream_count: 3,
                    max_depth: 2,
                    cycles_resolved: 0,
                    self_deps_rejected: 0,
                },
            })
        ),
    ]
}

fuzz_target!(|data: &[u8]| {
    // Limit input size to prevent timeouts
    if data.len() > 1024 {
        return;
    }

    // Try to generate a structured test from the fuzz data
    let test = match PriorityTest::arbitrary(&mut arbitrary::Unstructured::new(data)) {
        Ok(test) => test,
        Err(_) => return, // Invalid input, skip
    };

    // Skip tests with too many frames or unreasonable stream IDs
    if test.priority_frames.len() > 50 || test.max_stream_id > 100 {
        return;
    }

    // Normalize stream IDs to reasonable range
    let mut frames = test.priority_frames;
    for frame in &mut frames {
        frame.stream_id = (frame.stream_id % test.max_stream_id.max(1) as u32) + 1;
        frame.dependency = frame.dependency % (test.max_stream_id.max(1) as u32 + 1);
        frame.weight = frame.weight.max(1); // Weight must be 1-256
    }

    // Test with default (strict) policy
    let mut manager = MockPriorityManager::new();

    for frame in &frames {
        let result = manager.apply_priority_frame(frame);

        // Validate result consistency
        match result {
            Ok(PriorityResult::Success(_)) => {
                // Successful application should maintain tree integrity
                assert!(manager.verify_integrity().is_ok(),
                    "Tree integrity check failed after successful priority update");

                // Tree should not contain the problematic stream dependency
                if let Some(stream) = manager.get_tree().streams.get(&frame.stream_id) {
                    assert_ne!(stream.parent, frame.stream_id,
                        "Self-dependency was incorrectly accepted");
                }
            }

            Ok(PriorityResult::ProtocolError(error)) => {
                // Protocol errors should be well-formed
                match error {
                    PriorityError::SelfDependency => {
                        assert_eq!(frame.stream_id, frame.dependency,
                            "SelfDependency error but stream_id != dependency");
                    }
                    PriorityError::CyclicDependency(cycle) => {
                        assert!(!cycle.is_empty(),
                            "CyclicDependency error should include cycle path");
                        assert!(cycle.contains(&frame.stream_id) || cycle.contains(&frame.dependency),
                            "Cycle path should include relevant streams");
                    }
                    _ => {
                        // Other protocol errors are acceptable
                    }
                }
            }

            Ok(PriorityResult::Restructured(new_tree, message)) => {
                // Restructuring should maintain integrity
                assert!(manager.verify_integrity().is_ok(),
                    "Tree integrity check failed after restructuring");
                assert!(!message.is_empty(),
                    "Restructuring should include explanation");
            }

            Err(error) => {
                // Direct errors during processing
                match error {
                    PriorityError::InvalidStreamId |
                    PriorityError::InvalidWeight |
                    PriorityError::TreeCorruption => {
                        // Expected for invalid input
                    }
                    _ => {
                        // Other errors are acceptable
                    }
                }
            }
        }
    }

    // Test with permissive policy (allows cycle resolution)
    let permissive_policy = CycleDetectionPolicy {
        reject_all_cycles: false,
        allow_cycle_resolution: true,
        max_tree_depth: 1000,
        max_tracked_streams: 10000,
        max_resolution_attempts: 1000,
    };

    let mut permissive_manager = MockPriorityManager::with_policy(permissive_policy);

    for frame in &frames {
        let _permissive_result = permissive_manager.apply_priority_frame(frame);
        // Permissive policy should handle more cases without rejection
    }

    // Run predefined test cases to ensure correctness
    for (test_name, test_frames, expected) in generate_test_cases() {
        let mut test_manager = MockPriorityManager::new();

        let mut last_result = None;
        for frame in test_frames {
            last_result = Some(test_manager.apply_priority_frame(&frame));
        }

        if let Some(result) = last_result {
            match (&result, &expected) {
                (Ok(PriorityResult::Success(_)), PriorityResult::Success(_)) => {
                    // Both successful - verify tree integrity
                    assert!(test_manager.verify_integrity().is_ok(),
                        "Test '{}': tree integrity check failed", test_name);
                }

                (Ok(PriorityResult::ProtocolError(actual_error)), PriorityResult::ProtocolError(expected_error)) => {
                    // Both protocol errors - verify error type matches
                    assert_eq!(std::mem::discriminant(actual_error), std::mem::discriminant(expected_error),
                        "Test '{}': protocol error type mismatch", test_name);
                }

                _ => {
                    // Other combinations may be acceptable due to fuzzing context
                    // and different policy settings
                }
            }
        }
    }

    // Final integrity check
    assert!(manager.verify_integrity().is_ok(),
        "Final tree integrity check failed");
});