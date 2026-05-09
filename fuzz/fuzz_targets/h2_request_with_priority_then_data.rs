#![no_main]

//! Fuzz target for HTTP/2 request flow with PRIORITY + HEADERS + DATA frames
//!
//! Tests the interaction between PRIORITY, HEADERS, and DATA frames on the same
//! stream. Per RFC 7540 §5.3, PRIORITY frames can arrive before or after HEADERS
//! and should be handled differently in each case:
//! - Before HEADERS: treated as advisory weighting for upcoming request
//! - After HEADERS: updates current stream's priority weight
//!
//! Key test scenarios:
//! - PRIORITY → HEADERS → DATA flow on same stream
//! - HEADERS → PRIORITY → DATA flow on same stream
//! - Multiple PRIORITY frames with weight/dependency changes
//! - Stream dependency trees and exclusive dependencies
//! - Priority updates during active data transfer
//! - Edge cases with invalid priority configurations

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use std::collections::HashMap;

/// Mock HTTP/2 connection for testing priority + request flow
struct MockPriorityRequestConnection {
    /// Stream states and their priority information
    streams: HashMap<u32, StreamInfo>,

    /// Priority dependency tree
    priority_tree: PriorityTree,

    /// Statistics tracking
    stats: PriorityStats,

    /// Violation tracking
    violations: Vec<ViolationType>,
}

#[derive(Clone, Debug)]
struct StreamInfo {
    stream_id: u32,
    state: StreamState,
    priority: PriorityInfo,
    headers_received: bool,
    data_frames: Vec<DataFrame>,
    priority_updates: Vec<PriorityUpdate>,
}

#[derive(Clone, Debug)]
struct PriorityInfo {
    weight: u8,      // 1-256 (stored as 0-255, actual = weight + 1)
    dependency: u32, // Stream ID this stream depends on
    exclusive: bool, // Whether this is exclusive dependency
    advisory: bool,  // True if set before HEADERS (advisory)
}

#[derive(Clone, Debug)]
struct PriorityUpdate {
    timestamp: u32,
    old_priority: PriorityInfo,
    new_priority: PriorityInfo,
    before_headers: bool,
}

#[derive(Clone, Debug)]
struct DataFrame {
    data_length: u32,
    end_stream: bool,
    received_after_priority: bool,
}

#[derive(Default, Clone, Debug)]
struct PriorityTree {
    /// Stream dependencies (child -> parent)
    dependencies: HashMap<u32, u32>,

    /// Children of each stream
    children: HashMap<u32, Vec<u32>>,

    /// Exclusive dependencies
    exclusive_deps: HashMap<u32, bool>,
}

#[derive(Clone, Debug)]
enum StreamState {
    Idle,
    Open,
    HalfClosedRemote,
}

#[derive(Default, Clone, Debug)]
struct PriorityStats {
    priority_frames_received: u32,
    headers_frames_received: u32,
    data_frames_received: u32,
    priority_before_headers: u32, // Advisory weightings
    priority_after_headers: u32,  // Active weight updates
    priority_updates_during_data: u32,
    dependency_cycles_detected: u32,
    exclusive_dependencies: u32,
}

#[derive(Clone, Debug)]
enum ViolationType {
    DependencyCycle,
    SelfDependency,
    InvalidStreamState,
}

impl Default for PriorityInfo {
    fn default() -> Self {
        Self {
            weight: 15,    // Default weight is 16 (stored as 15)
            dependency: 0, // Default dependency is stream 0
            exclusive: false,
            advisory: false,
        }
    }
}

impl MockPriorityRequestConnection {
    fn new() -> Self {
        Self {
            streams: HashMap::new(),
            priority_tree: PriorityTree::default(),
            stats: PriorityStats::default(),
            violations: Vec::new(),
        }
    }

    /// Process a PRIORITY frame
    fn handle_priority(
        &mut self,
        stream_id: u32,
        weight: u8,
        dependency: u32,
        exclusive: bool,
    ) -> Result<(), H2Error> {
        self.stats.priority_frames_received += 1;

        // Validate weight (RFC 7540 §6.3: weight is 1-256, transmitted as 0-255)
        // We store as-is (0-255) and add 1 when using

        // Validate dependency
        if dependency == stream_id {
            self.violations.push(ViolationType::SelfDependency);
            return Err(H2Error::ProtocolError);
        }

        // Check for dependency cycles
        if self.would_create_cycle(stream_id, dependency) {
            self.violations.push(ViolationType::DependencyCycle);
            self.stats.dependency_cycles_detected += 1;
            return Err(H2Error::ProtocolError);
        }

        let priority_info = PriorityInfo {
            weight,
            dependency,
            exclusive,
            advisory: false, // Will be set based on stream state
        };

        // Get or create stream
        let stream = self.streams.entry(stream_id).or_insert_with(|| StreamInfo {
            stream_id,
            state: StreamState::Idle,
            priority: PriorityInfo::default(),
            headers_received: false,
            data_frames: Vec::new(),
            priority_updates: Vec::new(),
        });

        // Determine if this is advisory (before HEADERS) or active (after HEADERS)
        let is_advisory = !stream.headers_received;
        let mut new_priority = priority_info;
        new_priority.advisory = is_advisory;

        // Track the update
        let update = PriorityUpdate {
            timestamp: self.stats.priority_frames_received,
            old_priority: stream.priority.clone(),
            new_priority: new_priority.clone(),
            before_headers: is_advisory,
        };
        stream.priority_updates.push(update);

        // Update stream priority
        stream.priority = new_priority;

        // Update statistics
        if is_advisory {
            self.stats.priority_before_headers += 1;
        } else {
            self.stats.priority_after_headers += 1;

            // Check if this is during active data transfer
            if !stream.data_frames.is_empty() {
                self.stats.priority_updates_during_data += 1;
            }
        }

        if exclusive {
            self.stats.exclusive_dependencies += 1;
        }

        // Update priority tree
        self.update_priority_tree(stream_id, dependency, exclusive)?;

        Ok(())
    }

    /// Process a HEADERS frame
    fn handle_headers(
        &mut self,
        stream_id: u32,
        headers: HashMap<String, String>,
    ) -> Result<(), H2Error> {
        self.stats.headers_frames_received += 1;

        // Get or create stream
        let stream = self.streams.entry(stream_id).or_insert_with(|| StreamInfo {
            stream_id,
            state: StreamState::Idle,
            priority: PriorityInfo::default(),
            headers_received: false,
            data_frames: Vec::new(),
            priority_updates: Vec::new(),
        });

        // Validate required headers
        if !headers.contains_key(":method") || !headers.contains_key(":path") {
            return Err(H2Error::ProtocolError);
        }

        // Update stream state
        stream.state = StreamState::Open;
        stream.headers_received = true;

        // Any previous priority settings are now considered advisory
        for update in &mut stream.priority_updates {
            if update.before_headers {
                // This was correctly marked as advisory
            }
        }

        Ok(())
    }

    /// Process a DATA frame
    fn handle_data(
        &mut self,
        stream_id: u32,
        data_length: u32,
        end_stream: bool,
    ) -> Result<(), H2Error> {
        self.stats.data_frames_received += 1;

        let stream = self
            .streams
            .get_mut(&stream_id)
            .ok_or(H2Error::ProtocolError)?;

        // Validate stream state
        match stream.state {
            StreamState::Open | StreamState::HalfClosedRemote => {
                // Valid states for receiving DATA
            }
            _ => {
                self.violations.push(ViolationType::InvalidStreamState);
                return Err(H2Error::StreamClosed);
            }
        }

        // Check if HEADERS was received first
        if !stream.headers_received {
            return Err(H2Error::ProtocolError);
        }

        // Record the DATA frame
        let data_frame = DataFrame {
            data_length,
            end_stream,
            received_after_priority: !stream.priority_updates.is_empty(),
        };
        stream.data_frames.push(data_frame);

        // Update stream state if end_stream
        if end_stream {
            stream.state = match stream.state {
                StreamState::Open => StreamState::HalfClosedRemote,
                _ => stream.state.clone(),
            };
        }

        Ok(())
    }

    /// Check if adding a dependency would create a cycle
    fn would_create_cycle(&self, stream_id: u32, dependency: u32) -> bool {
        if dependency == 0 {
            return false; // Stream 0 is root, no cycle possible
        }

        // Follow the dependency chain to see if it leads back to stream_id
        let mut current = dependency;
        let mut visited = std::collections::HashSet::new();

        loop {
            if current == stream_id {
                return true; // Found a cycle
            }

            if visited.contains(&current) {
                return false; // Loop in existing tree, but not involving stream_id
            }

            visited.insert(current);

            // Get the dependency of current stream
            if let Some(stream) = self.streams.get(&current) {
                current = stream.priority.dependency;
                if current == 0 {
                    return false; // Reached root
                }
            } else {
                return false; // Stream doesn't exist, assume no cycle
            }
        }
    }

    /// Update the priority tree with new dependency
    fn update_priority_tree(
        &mut self,
        stream_id: u32,
        dependency: u32,
        exclusive: bool,
    ) -> Result<(), H2Error> {
        // Remove from old parent's children
        if let Some(old_dep) = self.priority_tree.dependencies.get(&stream_id)
            && let Some(children) = self.priority_tree.children.get_mut(old_dep)
        {
            children.retain(|&x| x != stream_id);
        }

        // Add to new parent
        self.priority_tree
            .dependencies
            .insert(stream_id, dependency);
        self.priority_tree
            .children
            .entry(dependency)
            .or_default()
            .push(stream_id);

        // Handle exclusive dependencies
        if exclusive {
            self.priority_tree.exclusive_deps.insert(stream_id, true);

            // Move existing children of dependency to be children of stream_id
            if let Some(existing_children) = self.priority_tree.children.get(&dependency).cloned() {
                for &child in &existing_children {
                    if child != stream_id {
                        self.priority_tree.dependencies.insert(child, stream_id);
                    }
                }
                // Clear old parent's children and add only this stream
                self.priority_tree
                    .children
                    .insert(dependency, vec![stream_id]);
                self.priority_tree.children.insert(
                    stream_id,
                    existing_children
                        .into_iter()
                        .filter(|&x| x != stream_id)
                        .collect(),
                );
            }
        } else {
            self.priority_tree.exclusive_deps.insert(stream_id, false);
        }

        Ok(())
    }

    /// Test complete request flow: PRIORITY → HEADERS → DATA
    fn test_priority_headers_data_flow(&mut self, stream_id: u32) -> FlowTestResult {
        let mut result = FlowTestResult::default();

        // Phase 1: Send PRIORITY (advisory)
        let priority_result = self.handle_priority(stream_id, 32, 0, false);
        result.priority_success = priority_result.is_ok();

        // Phase 2: Send HEADERS
        let mut headers = HashMap::new();
        headers.insert(":method".to_string(), "GET".to_string());
        headers.insert(":path".to_string(), "/test".to_string());
        headers.insert(":scheme".to_string(), "https".to_string());
        headers.insert(":authority".to_string(), "example.com".to_string());

        let headers_result = self.handle_headers(stream_id, headers);
        result.headers_success = headers_result.is_ok();

        // Phase 3: Send another PRIORITY (active update)
        let priority2_result = self.handle_priority(stream_id, 64, 0, false);
        result.priority_update_success = priority2_result.is_ok();

        // Phase 4: Send DATA
        let data_result = self.handle_data(stream_id, 1000, true);
        result.data_success = data_result.is_ok();

        // Validate the flow
        if let Some(stream) = self.streams.get(&stream_id) {
            result.advisory_priority_set = stream.priority_updates.iter().any(|u| u.before_headers);
            result.active_priority_set = stream.priority_updates.iter().any(|u| !u.before_headers);
            result.headers_received = stream.headers_received;
            result.data_frames_count = stream.data_frames.len() as u32;
        }

        result
    }

    /// Get comprehensive statistics
    fn get_stats(&self) -> &PriorityStats {
        &self.stats
    }

    /// Get all violations
    fn get_violations(&self) -> &[ViolationType] {
        &self.violations
    }

    /// Analyze priority tree for correctness
    fn analyze_priority_tree(&self) -> TreeAnalysis {
        TreeAnalysis {
            total_streams: self.streams.len() as u32,
            dependency_depth: self.calculate_max_depth(),
            cycles_detected: self.stats.dependency_cycles_detected,
            exclusive_count: self.stats.exclusive_dependencies,
            orphaned_streams: self.count_orphaned_streams(),
        }
    }

    fn calculate_max_depth(&self) -> u32 {
        let mut max_depth = 0;
        for &stream_id in self.streams.keys() {
            let depth = self.calculate_depth(stream_id);
            max_depth = max_depth.max(depth);
        }
        max_depth
    }

    fn calculate_depth(&self, stream_id: u32) -> u32 {
        let mut depth = 0;
        let mut current = stream_id;
        let mut visited = std::collections::HashSet::new();

        loop {
            if visited.contains(&current) {
                break; // Cycle detected, stop
            }
            visited.insert(current);

            if let Some(stream) = self.streams.get(&current) {
                current = stream.priority.dependency;
                if current == 0 {
                    break; // Reached root
                }
                depth += 1;
            } else {
                break;
            }
        }
        depth
    }

    fn count_orphaned_streams(&self) -> u32 {
        // Count streams that don't have their dependencies in the tree
        let mut orphaned = 0;
        for stream in self.streams.values() {
            if stream.priority.dependency != 0
                && !self.streams.contains_key(&stream.priority.dependency)
            {
                orphaned += 1;
            }
        }
        orphaned
    }
}

fn observe_priority_result(
    result: Result<(), H2Error>,
    before_stats: &PriorityStats,
    before_violations: usize,
    connection: &MockPriorityRequestConnection,
    stream_id: u32,
    dependency: u32,
) {
    let stats = connection.get_stats();
    assert_eq!(
        stats.priority_frames_received,
        before_stats.priority_frames_received + 1,
        "PRIORITY handler must account every attempted frame"
    );

    match result {
        Ok(()) => {
            assert_ne!(
                stream_id, dependency,
                "accepted PRIORITY must not be self-dependent"
            );
            assert!(
                connection.streams.contains_key(&stream_id),
                "accepted PRIORITY must create or update the target stream"
            );
            assert_eq!(
                connection.priority_tree.dependencies.get(&stream_id),
                Some(&dependency),
                "accepted PRIORITY must update the dependency tree"
            );
        }
        Err(H2Error::ProtocolError) => {
            assert!(
                stream_id == dependency
                    || stats.dependency_cycles_detected > before_stats.dependency_cycles_detected
                    || connection.get_violations().len() > before_violations,
                "rejected PRIORITY should be tied to a visible priority violation"
            );
        }
        Err(err) => panic!("unexpected PRIORITY handler error: {err:?}"),
    }
}

fn observe_headers_result(
    result: Result<(), H2Error>,
    before_stats: &PriorityStats,
    connection: &MockPriorityRequestConnection,
    stream_id: u32,
) {
    let stats = connection.get_stats();
    assert_eq!(
        stats.headers_frames_received,
        before_stats.headers_frames_received + 1,
        "HEADERS handler must account every attempted frame"
    );

    match result {
        Ok(()) => {
            let stream = connection
                .streams
                .get(&stream_id)
                .expect("accepted HEADERS must create or update the target stream");
            assert!(
                stream.headers_received,
                "accepted HEADERS must mark headers received"
            );
            assert!(
                matches!(stream.state, StreamState::Open),
                "accepted HEADERS must open the target stream"
            );
        }
        Err(err) => {
            let diagnostic = format!("{err:?}");
            assert!(
                !diagnostic.trim().is_empty(),
                "rejected HEADERS should expose a visible diagnostic"
            );
        }
    }
}

fn observe_data_result(
    result: Result<(), H2Error>,
    before_stats: &PriorityStats,
    connection: &MockPriorityRequestConnection,
    stream_id: u32,
) {
    let stats = connection.get_stats();
    assert_eq!(
        stats.data_frames_received,
        before_stats.data_frames_received + 1,
        "DATA handler must account every attempted frame"
    );

    match result {
        Ok(()) => {
            let stream = connection
                .streams
                .get(&stream_id)
                .expect("accepted DATA must target an existing stream");
            assert!(stream.headers_received, "accepted DATA must follow HEADERS");
            assert!(
                !stream.data_frames.is_empty(),
                "accepted DATA must be retained in the stream record"
            );
        }
        Err(err) => {
            let diagnostic = format!("{err:?}");
            assert!(
                !diagnostic.trim().is_empty(),
                "rejected DATA should expose a visible diagnostic"
            );
        }
    }
}

#[derive(Default, Clone, Debug)]
struct FlowTestResult {
    priority_success: bool,
    headers_success: bool,
    priority_update_success: bool,
    data_success: bool,
    advisory_priority_set: bool,
    active_priority_set: bool,
    headers_received: bool,
    data_frames_count: u32,
}

#[derive(Clone, Debug)]
struct TreeAnalysis {
    total_streams: u32,
    dependency_depth: u32,
    cycles_detected: u32,
    exclusive_count: u32,
    orphaned_streams: u32,
}

#[derive(Clone, Debug)]
enum H2Error {
    ProtocolError,
    StreamClosed,
}

/// Fuzz input structure
#[derive(Arbitrary, Debug, Clone)]
struct FuzzInput {
    /// Sequence of frame operations
    operations: Vec<FrameOperation>,

    /// Whether to test complete flows
    test_complete_flows: bool,

    /// Stream IDs to use for testing
    stream_ids: Vec<u32>,
}

#[derive(Arbitrary, Debug, Clone)]
enum FrameOperation {
    /// Send PRIORITY frame
    Priority {
        stream_id: u32,
        weight: u8,
        dependency: u32,
        exclusive: bool,
    },

    /// Send HEADERS frame
    Headers {
        stream_id: u32,
        method: String,
        path: String,
    },

    /// Send DATA frame
    Data {
        stream_id: u32,
        data_length: u32,
        end_stream: bool,
    },

    /// Test complete flow on stream
    TestFlow { stream_id: u32 },
}

fuzz_target!(|input: FuzzInput| {
    // Limit input size to prevent excessive resource usage
    if input.operations.len() > 100 {
        return;
    }

    let mut connection = MockPriorityRequestConnection::new();

    // Process operations
    for operation in input.operations {
        match operation {
            FrameOperation::Priority {
                stream_id,
                weight,
                dependency,
                exclusive,
            } => {
                // Sanitize inputs
                let safe_stream_id = (stream_id % 1000) + 1; // Stream IDs 1-1000
                let safe_dependency = dependency % 1000; // Dependencies 0-999 (0 is root)

                let before_stats = connection.get_stats().clone();
                let before_violations = connection.get_violations().len();
                let result =
                    connection.handle_priority(safe_stream_id, weight, safe_dependency, exclusive);
                observe_priority_result(
                    result,
                    &before_stats,
                    before_violations,
                    &connection,
                    safe_stream_id,
                    safe_dependency,
                );
            }

            FrameOperation::Headers {
                stream_id,
                method,
                path,
            } => {
                let safe_stream_id = (stream_id % 1000) + 1;

                // Sanitize method and path
                let safe_method = if method.is_empty() {
                    "GET".to_string()
                } else {
                    method.chars().take(10).collect()
                };
                let safe_path = if path.is_empty() {
                    "/".to_string()
                } else {
                    format!("/{}", path.chars().take(50).collect::<String>())
                };

                let mut headers = HashMap::new();
                headers.insert(":method".to_string(), safe_method);
                headers.insert(":path".to_string(), safe_path);
                headers.insert(":scheme".to_string(), "https".to_string());
                headers.insert(":authority".to_string(), "example.com".to_string());

                let before_stats = connection.get_stats().clone();
                let result = connection.handle_headers(safe_stream_id, headers);
                observe_headers_result(result, &before_stats, &connection, safe_stream_id);
            }

            FrameOperation::Data {
                stream_id,
                data_length,
                end_stream,
            } => {
                let safe_stream_id = (stream_id % 1000) + 1;
                let safe_length = data_length.min(1000000); // Max 1MB per frame

                let before_stats = connection.get_stats().clone();
                let result = connection.handle_data(safe_stream_id, safe_length, end_stream);
                observe_data_result(result, &before_stats, &connection, safe_stream_id);
            }

            FrameOperation::TestFlow { stream_id } => {
                let safe_stream_id = (stream_id % 1000) + 1;
                let _flow_result = connection.test_priority_headers_data_flow(safe_stream_id);
            }
        }
    }

    // Run complete flow tests if requested
    if input.test_complete_flows {
        for stream_id in input.stream_ids.iter().take(10) {
            let safe_stream_id = (stream_id % 1000) + 1;
            let _flow_result = connection.test_priority_headers_data_flow(safe_stream_id);
        }
    }

    // Validate final state
    let stats = connection.get_stats();
    let violations = connection.get_violations();

    // Check for critical violations
    for violation in violations {
        match violation {
            ViolationType::DependencyCycle => {
                // Dependency cycles should be detected and rejected
                assert!(stats.dependency_cycles_detected > 0);
            }
            ViolationType::SelfDependency => {
                // Self-dependencies should be rejected
            }
            ViolationType::InvalidStreamState => {
                // DATA on idle or otherwise inactive streams should be rejected
            }
        }
    }

    // Analyze priority tree
    let tree_analysis = connection.analyze_priority_tree();

    // Ensure tree depth is reasonable (prevent stack overflow in real implementation)
    assert!(
        tree_analysis.dependency_depth < 1000,
        "Priority tree too deep: {}",
        tree_analysis.dependency_depth
    );
    assert_eq!(
        tree_analysis.total_streams as usize,
        connection.streams.len(),
        "tree analysis stream count should match connection stream map"
    );
    assert_eq!(
        tree_analysis.cycles_detected, stats.dependency_cycles_detected,
        "tree analysis should preserve detected cycle count"
    );
    assert_eq!(
        tree_analysis.exclusive_count, stats.exclusive_dependencies,
        "tree analysis should preserve exclusive dependency count"
    );
    assert!(
        tree_analysis.orphaned_streams <= tree_analysis.total_streams,
        "orphaned streams cannot exceed total streams"
    );

    // Test priority semantics
    test_priority_semantics(&connection);
});

/// Test priority semantic correctness
fn test_priority_semantics(connection: &MockPriorityRequestConnection) {
    for stream in connection.streams.values() {
        // Convert stored weight to HTTP/2's actual 1-256 range.
        let actual_weight = usize::from(stream.priority.weight) + 1;
        assert!(
            (1..=usize::from(u8::MAX) + 1).contains(&actual_weight),
            "actual priority weight out of range: {actual_weight}"
        );

        if stream.priority.exclusive {
            assert_eq!(
                connection
                    .priority_tree
                    .exclusive_deps
                    .get(&stream.stream_id),
                Some(&true),
                "exclusive stream priority must be reflected in the tree"
            );
        }

        // Verify no self-dependency
        assert_ne!(
            stream.stream_id, stream.priority.dependency,
            "Self-dependency detected"
        );

        // Check priority update semantics
        for update in &stream.priority_updates {
            assert!(
                update.timestamp > 0,
                "priority updates must retain ordering metadata"
            );
            assert_ne!(
                stream.stream_id, update.old_priority.dependency,
                "old priority snapshot must not contain self-dependency"
            );

            if update.before_headers {
                // Advisory priority - should be applied when stream becomes active
                assert!(update.new_priority.advisory);
            } else {
                // Active priority update - should affect current stream scheduling
                assert!(!update.new_priority.advisory);
            }
        }

        // Verify HEADERS/DATA relationship
        if !stream.data_frames.is_empty() {
            assert!(stream.headers_received, "DATA received before HEADERS");
        }

        for data_frame in &stream.data_frames {
            assert!(
                data_frame.data_length <= 1_000_000,
                "sanitized DATA length should stay bounded"
            );
            if data_frame.end_stream {
                assert!(
                    matches!(stream.state, StreamState::HalfClosedRemote),
                    "END_STREAM DATA should half-close the receiving side"
                );
            }
            assert_eq!(
                data_frame.received_after_priority,
                !stream.priority_updates.is_empty(),
                "DATA priority marker should reflect the stream priority history"
            );
        }
    }
}
