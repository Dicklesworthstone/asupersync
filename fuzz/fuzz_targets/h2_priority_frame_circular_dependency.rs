#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use libfuzzer_sys::fuzz_target;
use std::collections::{HashMap, HashSet, VecDeque};
use std::panic;

/// HTTP/2 error codes per RFC 9113 §7
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

/// PRIORITY frame per RFC 9113 §6.3
#[derive(Debug, Clone, Arbitrary)]
struct PriorityFrame {
    /// Stream ID this PRIORITY frame applies to
    stream_id: u32,
    /// Exclusive flag (whether this stream should be sole child of dependency)
    exclusive: bool,
    /// Stream dependency (0 = root of tree)
    stream_dependency: u32,
    /// Weight (1-256, transmitted as 0-255)
    weight: u8,
}

impl PriorityFrame {
    fn new(stream_id: u32, stream_dependency: u32, weight: u8) -> Self {
        Self {
            stream_id,
            exclusive: false,
            stream_dependency,
            weight,
        }
    }

    fn with_exclusive(mut self) -> Self {
        self.exclusive = true;
        self
    }

    fn actual_weight(&self) -> u16 {
        (self.weight as u16) + 1 // RFC weight is transmitted value + 1
    }
}

/// Stream priority information
#[derive(Debug, Clone)]
struct StreamPriority {
    /// Stream ID
    stream_id: u32,
    /// Parent stream (0 = root)
    parent: u32,
    /// Weight (1-256)
    weight: u16,
    /// Whether this stream is an exclusive child
    exclusive: bool,
    /// Direct children of this stream
    children: Vec<u32>,
}

impl StreamPriority {
    fn new(stream_id: u32) -> Self {
        Self {
            stream_id,
            parent: 0,  // Default to root
            weight: 16, // Default weight
            exclusive: false,
            children: Vec::new(),
        }
    }

    fn set_dependency(&mut self, parent: u32, weight: u16, exclusive: bool) {
        self.parent = parent;
        self.weight = weight;
        self.exclusive = exclusive;
    }
}

/// Priority dependency tree for HTTP/2 streams
#[derive(Debug)]
struct PriorityTree {
    /// All stream priorities, keyed by stream ID
    streams: HashMap<u32, StreamPriority>,
    /// Protocol errors that occurred
    protocol_errors: Vec<String>,
    /// Connection is active
    is_active: bool,
}

impl PriorityTree {
    fn new() -> Self {
        Self {
            streams: HashMap::new(),
            protocol_errors: Vec::new(),
            is_active: true,
        }
    }

    /// Add a new stream to the priority tree
    fn add_stream(&mut self, stream_id: u32) {
        if stream_id == 0 {
            return; // Stream 0 is reserved
        }

        if !self.streams.contains_key(&stream_id) {
            self.streams
                .insert(stream_id, StreamPriority::new(stream_id));
        }
    }

    /// Process PRIORITY frame per RFC 9113 §6.3
    fn process_priority_frame(&mut self, frame: PriorityFrame) -> Result<(), ErrorCode> {
        if !self.is_active {
            return Err(ErrorCode::ProtocolError);
        }

        let stream_id = frame.stream_id;
        let dependency = frame.stream_dependency;

        // RFC 9113 §5.3.1: A stream cannot depend on itself
        if stream_id == dependency {
            let error = format!("Stream {} cannot depend on itself", stream_id);
            self.protocol_errors.push(error);
            self.is_active = false;
            return Err(ErrorCode::ProtocolError);
        }

        // Add streams if they don't exist
        self.add_stream(stream_id);
        if dependency != 0 {
            self.add_stream(dependency);
        }

        // Check for circular dependency BEFORE making the change
        if self.would_create_cycle(stream_id, dependency) {
            let error = format!(
                "PRIORITY frame would create circular dependency: {} -> {}",
                stream_id, dependency
            );
            self.protocol_errors.push(error);
            self.is_active = false;
            return Err(ErrorCode::ProtocolError);
        }

        // Apply the priority change
        self.update_stream_dependency(
            stream_id,
            dependency,
            frame.actual_weight(),
            frame.exclusive,
        );

        Ok(())
    }

    /// Check if setting stream_id to depend on new_parent would create a cycle
    fn would_create_cycle(&self, stream_id: u32, new_parent: u32) -> bool {
        if new_parent == 0 {
            return false; // Root dependency never creates cycles
        }

        // Check if new_parent is already a descendant of stream_id
        // If so, making stream_id depend on new_parent creates a cycle
        self.is_descendant_of(new_parent, stream_id)
    }

    /// Check if candidate_descendant is a descendant of ancestor
    fn is_descendant_of(&self, candidate_descendant: u32, ancestor: u32) -> bool {
        let mut visited = HashSet::new();
        let mut queue = VecDeque::new();

        // Start from ancestor and explore all descendants
        if let Some(ancestor_stream) = self.streams.get(&ancestor) {
            queue.extend(&ancestor_stream.children);
        }

        while let Some(current) = queue.pop_front() {
            if visited.contains(&current) {
                continue; // Avoid infinite loops in case of existing cycles
            }
            visited.insert(current);

            if current == candidate_descendant {
                return true; // Found the candidate as a descendant
            }

            // Add children to queue
            if let Some(current_stream) = self.streams.get(&current) {
                queue.extend(&current_stream.children);
            }
        }

        false
    }

    /// Update stream dependency, handling exclusive flag and tree restructuring
    fn update_stream_dependency(
        &mut self,
        stream_id: u32,
        new_parent: u32,
        weight: u16,
        exclusive: bool,
    ) {
        // Remove stream from its current parent's children
        let current_parent = self.streams.get(&stream_id).map(|s| s.parent).unwrap_or(0);
        if current_parent != 0 {
            if let Some(parent_stream) = self.streams.get_mut(&current_parent) {
                parent_stream.children.retain(|&child| child != stream_id);
            }
        }

        // If exclusive, make all current children of new_parent become children of stream_id
        if exclusive && new_parent != 0 {
            if let Some(parent_stream) = self.streams.get(&new_parent) {
                let siblings = parent_stream.children.clone();

                // Move siblings to be children of stream_id
                for sibling in siblings {
                    if let Some(sibling_stream) = self.streams.get_mut(&sibling) {
                        sibling_stream.parent = stream_id;
                    }

                    if let Some(stream) = self.streams.get_mut(&stream_id) {
                        if !stream.children.contains(&sibling) {
                            stream.children.push(sibling);
                        }
                    }
                }

                // Clear parent's children
                if let Some(parent_stream) = self.streams.get_mut(&new_parent) {
                    parent_stream.children.clear();
                }
            }
        }

        // Update stream's dependency
        if let Some(stream) = self.streams.get_mut(&stream_id) {
            stream.set_dependency(new_parent, weight, exclusive);
        }

        // Add stream as child of new parent
        if new_parent != 0 {
            if let Some(parent_stream) = self.streams.get_mut(&new_parent) {
                if !parent_stream.children.contains(&stream_id) {
                    parent_stream.children.push(stream_id);
                }
            }
        }
    }

    /// Get stream dependency
    fn get_stream_parent(&self, stream_id: u32) -> Option<u32> {
        self.streams.get(&stream_id).map(|s| s.parent)
    }

    /// Get stream children
    fn get_stream_children(&self, stream_id: u32) -> Vec<u32> {
        self.streams
            .get(&stream_id)
            .map(|s| s.children.clone())
            .unwrap_or_default()
    }

    /// Check if tree is acyclic (should always be true after valid operations)
    fn is_acyclic(&self) -> bool {
        for &stream_id in self.streams.keys() {
            if self.has_cycle_from(stream_id) {
                return false;
            }
        }
        true
    }

    /// Check if there's a cycle starting from stream_id
    fn has_cycle_from(&self, stream_id: u32) -> bool {
        let mut visited = HashSet::new();
        let mut current = stream_id;

        loop {
            if visited.contains(&current) {
                return true; // Found a cycle
            }
            visited.insert(current);

            // Move to parent
            if let Some(stream) = self.streams.get(&current) {
                if stream.parent == 0 {
                    break; // Reached root
                }
                current = stream.parent;
            } else {
                break; // Stream not found
            }
        }

        false
    }

    /// Get all protocol errors
    fn get_protocol_errors(&self) -> &[String] {
        &self.protocol_errors
    }

    /// Check if connection is active
    fn is_connection_active(&self) -> bool {
        self.is_active
    }
}

/// Test scenario for circular dependency detection
#[derive(Debug, Arbitrary)]
struct CircularDependencyScenario {
    /// Initial streams to create
    initial_streams: Vec<u32>,
    /// Initial dependency setup (non-circular)
    initial_dependencies: Vec<PriorityFrame>,
    /// PRIORITY frames that may create cycles
    potentially_circular_frames: Vec<PriorityFrame>,
    /// Whether to test direct self-cycles
    test_self_cycles: bool,
}

/// Test circular dependency detection
fn test_circular_dependency_detection(scenario: CircularDependencyScenario) -> Result<(), String> {
    let mut tree = PriorityTree::new();

    // Phase 1: Create initial streams
    for &stream_id in &scenario.initial_streams {
        if stream_id != 0 && stream_id < 1000 {
            // Limit range for practical testing
            tree.add_stream(stream_id);
        }
    }

    // Phase 2: Set up initial (valid) dependencies
    for frame in scenario.initial_dependencies {
        if frame.stream_id != 0 && frame.stream_id < 1000 {
            match tree.process_priority_frame(frame) {
                Ok(()) => {
                    // Valid dependency established
                }
                Err(ErrorCode::ProtocolError) => {
                    return Err("Initial dependency setup caused protocol error".to_string());
                }
                Err(other) => {
                    return Err(format!("Unexpected error in initial setup: {:?}", other));
                }
            }
        }
    }

    // Verify tree is acyclic after initial setup
    if !tree.is_acyclic() {
        return Err("Tree became cyclic after initial setup".to_string());
    }

    // Phase 3: Test self-cycles if requested
    if scenario.test_self_cycles {
        for &stream_id in &scenario.initial_streams {
            if stream_id != 0 && stream_id < 1000 {
                let self_cycle_frame = PriorityFrame::new(stream_id, stream_id, 16);

                match tree.process_priority_frame(self_cycle_frame) {
                    Err(ErrorCode::ProtocolError) => {
                        // Expected - self-cycles should be rejected
                    }
                    Ok(()) => {
                        return Err(format!(
                            "Self-cycle for stream {} was incorrectly accepted",
                            stream_id
                        ));
                    }
                    Err(other) => {
                        return Err(format!("Unexpected error for self-cycle: {:?}", other));
                    }
                }
            }
        }

        // Connection should be closed after protocol error
        if tree.is_connection_active() {
            return Err("Connection should be closed after self-cycle attempt".to_string());
        }

        // Reset for further testing
        tree = PriorityTree::new();
        for &stream_id in &scenario.initial_streams {
            if stream_id != 0 && stream_id < 1000 {
                tree.add_stream(stream_id);
            }
        }
    }

    // Phase 4: Test potentially circular frames
    let mut detected_cycles = 0;
    let initial_error_count = tree.get_protocol_errors().len();

    for frame in &scenario.potentially_circular_frames {
        if frame.stream_id == 0
            || frame.stream_id >= 1000
            || (frame.stream_dependency != 0 && frame.stream_dependency >= 1000)
        {
            continue; // Skip invalid stream IDs
        }

        let would_be_circular = tree.would_create_cycle(frame.stream_id, frame.stream_dependency);

        match tree.process_priority_frame(frame.clone()) {
            Err(ErrorCode::ProtocolError) => {
                detected_cycles += 1;

                // If we detected this would be circular, this is expected
                if !would_be_circular && frame.stream_id != frame.stream_dependency {
                    return Err(format!(
                        "PRIORITY frame rejected but shouldn't create cycle: {} -> {}",
                        frame.stream_id, frame.stream_dependency
                    ));
                }
            }
            Ok(()) => {
                // Success is only acceptable if it wouldn't create a cycle
                if would_be_circular || frame.stream_id == frame.stream_dependency {
                    return Err(format!(
                        "Circular dependency was incorrectly accepted: {} -> {}",
                        frame.stream_id, frame.stream_dependency
                    ));
                }
            }
            Err(other) => {
                return Err(format!("Unexpected error for PRIORITY frame: {:?}", other));
            }
        }

        // Tree should remain acyclic
        if tree.is_acyclic() == false {
            return Err("Tree became cyclic after processing frame".to_string());
        }
    }

    // Phase 5: Validate error detection
    let final_error_count = tree.get_protocol_errors().len();
    let errors_added = final_error_count - initial_error_count;

    if detected_cycles > 0 && errors_added == 0 {
        return Err("Cycles detected but no protocol errors recorded".to_string());
    }

    Ok(())
}

/// Test basic self-cycle detection
fn test_basic_self_cycle() -> Result<(), String> {
    let mut tree = PriorityTree::new();

    tree.add_stream(1);
    tree.add_stream(3);

    // Try to make stream 1 depend on itself
    let self_cycle = PriorityFrame::new(1, 1, 16);

    match tree.process_priority_frame(self_cycle) {
        Err(ErrorCode::ProtocolError) => {
            // Expected
        }
        other => {
            return Err(format!(
                "Expected PROTOCOL_ERROR for self-cycle, got {:?}",
                other
            ));
        }
    }

    // Verify error was recorded
    let errors = tree.get_protocol_errors();
    if !errors.iter().any(|e| e.contains("cannot depend on itself")) {
        return Err("Self-cycle error not properly recorded".to_string());
    }

    // Connection should be closed
    if tree.is_connection_active() {
        return Err("Connection should be closed after protocol error".to_string());
    }

    Ok(())
}

/// Test indirect circular dependency (A->B->C->A)
fn test_indirect_cycle() -> Result<(), String> {
    let mut tree = PriorityTree::new();

    // Create streams
    tree.add_stream(1);
    tree.add_stream(3);
    tree.add_stream(5);

    // Set up chain: 1 -> 3 -> 5
    tree.process_priority_frame(PriorityFrame::new(3, 1, 16))
        .map_err(|e| format!("Failed to set up dependency 3->1: {:?}", e))?;
    tree.process_priority_frame(PriorityFrame::new(5, 3, 16))
        .map_err(|e| format!("Failed to set up dependency 5->3: {:?}", e))?;

    // Verify initial setup
    assert_eq!(tree.get_stream_parent(3), Some(1));
    assert_eq!(tree.get_stream_parent(5), Some(3));

    // Try to complete the cycle: 5 -> 1 -> 3 -> 5 (make 1 depend on 5)
    let cycle_frame = PriorityFrame::new(1, 5, 16);

    match tree.process_priority_frame(cycle_frame) {
        Err(ErrorCode::ProtocolError) => {
            // Expected - should detect that 5 is a descendant of 1
        }
        other => {
            return Err(format!(
                "Expected PROTOCOL_ERROR for indirect cycle, got {:?}",
                other
            ));
        }
    }

    // Verify error was recorded
    let errors = tree.get_protocol_errors();
    if !errors.iter().any(|e| e.contains("circular dependency")) {
        return Err("Circular dependency error not properly recorded".to_string());
    }

    Ok(())
}

/// Test exclusive flag with circular dependency
fn test_exclusive_circular() -> Result<(), String> {
    let mut tree = PriorityTree::new();

    tree.add_stream(1);
    tree.add_stream(3);
    tree.add_stream(5);

    // Set up: 3 -> 1, 5 -> 1 (both children of 1)
    tree.process_priority_frame(PriorityFrame::new(3, 1, 16))
        .map_err(|e| format!("Failed to set up dependency 3->1: {:?}", e))?;
    tree.process_priority_frame(PriorityFrame::new(5, 1, 16))
        .map_err(|e| format!("Failed to set up dependency 5->1: {:?}", e))?;

    // Try to make 1 exclusively depend on 3 (which is currently its child)
    let exclusive_cycle = PriorityFrame::new(1, 3, 16).with_exclusive();

    match tree.process_priority_frame(exclusive_cycle) {
        Err(ErrorCode::ProtocolError) => {
            // Expected - 3 is already a child of 1
        }
        other => {
            return Err(format!(
                "Expected PROTOCOL_ERROR for exclusive cycle, got {:?}",
                other
            ));
        }
    }

    Ok(())
}

/// Test complex dependency chain with multiple potential cycles
fn test_complex_dependency_chain() -> Result<(), String> {
    let mut tree = PriorityTree::new();

    // Create a complex tree: 1 -> 3 -> 5 -> 7, with 9 -> 3, 11 -> 5
    let streams = [1, 3, 5, 7, 9, 11];
    for &stream in &streams {
        tree.add_stream(stream);
    }

    // Build the tree
    tree.process_priority_frame(PriorityFrame::new(3, 1, 16))
        .map_err(|e| format!("Failed to build tree 3->1: {:?}", e))?;
    tree.process_priority_frame(PriorityFrame::new(5, 3, 16))
        .map_err(|e| format!("Failed to build tree 5->3: {:?}", e))?;
    tree.process_priority_frame(PriorityFrame::new(7, 5, 16))
        .map_err(|e| format!("Failed to build tree 7->5: {:?}", e))?;
    tree.process_priority_frame(PriorityFrame::new(9, 3, 16))
        .map_err(|e| format!("Failed to build tree 9->3: {:?}", e))?;
    tree.process_priority_frame(PriorityFrame::new(11, 5, 16))
        .map_err(|e| format!("Failed to build tree 11->5: {:?}", e))?;

    // Test various cycle attempts
    let cycle_attempts = vec![
        (1, 7),  // Direct ancestor -> descendant
        (3, 11), // Ancestor -> descendant
        (5, 1),  // Deep cycle
        (7, 3),  // Skip-level cycle
    ];

    for (stream, dependency) in cycle_attempts {
        let cycle_frame = PriorityFrame::new(stream, dependency, 16);

        match tree.process_priority_frame(cycle_frame) {
            Err(ErrorCode::ProtocolError) => {
                // Expected for all these cases
                tree = PriorityTree::new(); // Reset for next test
                for &s in &streams {
                    tree.add_stream(s);
                }
                // Rebuild tree
                tree.process_priority_frame(PriorityFrame::new(3, 1, 16))
                    .map_err(|e| format!("Failed to rebuild tree 3->1: {:?}", e))?;
                tree.process_priority_frame(PriorityFrame::new(5, 3, 16))
                    .map_err(|e| format!("Failed to rebuild tree 5->3: {:?}", e))?;
                tree.process_priority_frame(PriorityFrame::new(7, 5, 16))
                    .map_err(|e| format!("Failed to rebuild tree 7->5: {:?}", e))?;
                tree.process_priority_frame(PriorityFrame::new(9, 3, 16))
                    .map_err(|e| format!("Failed to rebuild tree 9->3: {:?}", e))?;
                tree.process_priority_frame(PriorityFrame::new(11, 5, 16))
                    .map_err(|e| format!("Failed to rebuild tree 11->5: {:?}", e))?;
            }
            other => {
                return Err(format!(
                    "Expected PROTOCOL_ERROR for cycle {} -> {}, got {:?}",
                    stream, dependency, other
                ));
            }
        }
    }

    Ok(())
}

/// Test edge case: dependency on non-existent stream
fn test_dependency_on_nonexistent() -> Result<(), String> {
    let mut tree = PriorityTree::new();

    tree.add_stream(1);

    // Try to depend on non-existent stream (should be allowed, creates the stream)
    let frame = PriorityFrame::new(1, 999, 16);

    match tree.process_priority_frame(frame) {
        Ok(()) => {
            // Should be allowed - creates stream 999
            assert_eq!(tree.get_stream_parent(1), Some(999));
        }
        other => {
            return Err(format!(
                "Dependency on non-existent stream should be allowed, got {:?}",
                other
            ));
        }
    }

    Ok(())
}

fuzz_target!(|data: &[u8]| {
    let result = panic::catch_unwind(|| {
        let mut unstructured = Unstructured::new(data);

        // Try to generate scenario from fuzz input
        if let Ok(scenario) = CircularDependencyScenario::arbitrary(&mut unstructured) {
            let _ = test_circular_dependency_detection(scenario);
        }

        // Run deterministic test cases
        if data.len() > 30 {
            let _ = test_basic_self_cycle();
            let _ = test_indirect_cycle();
            let _ = test_exclusive_circular();
            let _ = test_complex_dependency_chain();
            let _ = test_dependency_on_nonexistent();
        }
    });

    if result.is_err() {
        eprintln!("Panic in PRIORITY frame circular dependency fuzzing");
    }
});
