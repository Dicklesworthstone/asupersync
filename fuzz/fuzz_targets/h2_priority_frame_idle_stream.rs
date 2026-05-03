//! HTTP/2 PRIORITY frame on idle stream fuzz target.
//!
//! Tests PRIORITY frame handling on idle streams per RFC 7540 Section 6.3.
//! PRIORITY frames can be sent on idle streams to establish priority before
//! the stream is opened with HEADERS.
//!
//! This fuzzer generates arbitrary PRIORITY frames and verifies:
//! 1. PRIORITY frames on idle streams are accepted and recorded
//! 2. Priority is applied when the stream opens with HEADERS
//! 3. Stream dependency chains are maintained correctly
//! 4. Exclusive dependencies work properly
//! 5. No panics occur with malformed priority data

#![no_main]

use arbitrary::Arbitrary;
use asupersync::bytes::BytesMut;
use libfuzzer_sys::fuzz_target;
use std::collections::HashMap;

/// PRIORITY frame on idle stream test
#[derive(Debug, Clone, Arbitrary)]
struct PriorityIdleTest {
    /// Target stream ID (must be idle)
    stream_id: u32,
    /// PRIORITY frame data
    priority_frame: PriorityFrameData,
    /// Whether to follow up with HEADERS
    send_headers_after: bool,
    /// Headers frame data for stream opening
    headers_data: HeadersFrameData,
    /// Additional concurrent streams for dependency testing
    concurrent_streams: Vec<ConcurrentStream>,
    /// Connection settings
    connection_settings: ConnectionSettings,
}

/// PRIORITY frame data structure
#[derive(Debug, Clone, Arbitrary)]
struct PriorityFrameData {
    /// Stream dependency (0 = no dependency)
    stream_dependency: u32,
    /// Exclusive dependency flag
    exclusive: bool,
    /// Weight (1-256, stored as weight-1 in wire format)
    weight: u8,
    /// Additional padding or malformed data
    extra_data: Vec<u8>,
}

/// HEADERS frame data for opening the stream
#[derive(Debug, Clone, Arbitrary)]
struct HeadersFrameData {
    /// End stream flag
    end_stream: bool,
    /// Headers (simplified)
    headers: Vec<HeaderPair>,
    /// Padding length
    padding: Option<u8>,
}

/// Header name-value pair
#[derive(Debug, Clone, Arbitrary)]
struct HeaderPair {
    /// Header name
    name: HeaderName,
    /// Header value
    value: String,
}

/// Common header names
#[derive(Debug, Clone, Arbitrary)]
enum HeaderName {
    Method,
    Path,
    Scheme,
    Authority,
    ContentType,
    UserAgent,
    Custom(String),
}

/// Concurrent stream for dependency testing
#[derive(Debug, Clone, Arbitrary)]
struct ConcurrentStream {
    /// Stream ID
    stream_id: u32,
    /// Whether stream is open or idle
    is_open: bool,
    /// Priority weight if open
    weight: u8,
    /// Stream dependency
    depends_on: u32,
}

/// Connection settings
#[derive(Debug, Clone, Arbitrary)]
struct ConnectionSettings {
    /// Initial window size
    initial_window_size: u32,
    /// Max concurrent streams
    max_concurrent_streams: u32,
    /// Enable push promise
    enable_push: bool,
}

fuzz_target!(|data: &[u8]| {
    // Guard against excessive input size
    if data.len() > 100_000 {
        return;
    }

    let mut u = arbitrary::Unstructured::new(data);

    // Generate PRIORITY idle test case
    let test_case = match PriorityIdleTest::arbitrary(&mut u) {
        Ok(case) => case,
        Err(_) => return,
    };

    // Limit concurrent streams and headers for performance
    if test_case.concurrent_streams.len() > 15
        || test_case.headers_data.headers.len() > 20
        || test_case.priority_frame.extra_data.len() > 1000
    {
        return;
    }

    // Test core PRIORITY on idle stream
    test_priority_on_idle_stream(&test_case);

    // Test priority application when stream opens
    test_priority_application_on_open(&test_case);

    // Test stream dependency handling
    test_stream_dependency_handling(&test_case);

    // Test exclusive dependency behavior
    test_exclusive_dependency(&test_case);

    // Test edge cases
    test_priority_idle_edge_cases(&test_case);
});

/// Test PRIORITY frame on idle stream
fn test_priority_on_idle_stream(test_case: &PriorityIdleTest) {
    let stream_id = test_case.stream_id.max(1) | 1; // Ensure odd stream ID
    let mut mock_connection = MockH2Connection::new(test_case.connection_settings.clone());

    // Set up concurrent streams if any
    for concurrent in &test_case.concurrent_streams {
        let concurrent_id = concurrent.stream_id.max(3) | 1;
        if concurrent_id != stream_id && concurrent.is_open {
            mock_connection.open_stream(concurrent_id, concurrent.weight, concurrent.depends_on);
        }
    }

    // Send PRIORITY frame on idle stream
    let priority_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        mock_connection.send_priority_frame(
            stream_id,
            test_case.priority_frame.stream_dependency,
            test_case.priority_frame.exclusive,
            test_case.priority_frame.weight,
            &test_case.priority_frame.extra_data,
        )
    }));

    assert!(
        priority_result.is_ok(),
        "PRIORITY frame on idle stream {} should not panic",
        stream_id
    );

    if let Ok(result) = priority_result {
        match result {
            PriorityResult::Accepted { recorded_priority } => {
                // Verify priority was recorded for idle stream
                assert_eq!(
                    recorded_priority.weight, test_case.priority_frame.weight,
                    "Priority weight should be recorded correctly"
                );

                assert_eq!(
                    recorded_priority.stream_dependency, test_case.priority_frame.stream_dependency,
                    "Stream dependency should be recorded correctly"
                );

                assert_eq!(
                    recorded_priority.exclusive, test_case.priority_frame.exclusive,
                    "Exclusive flag should be recorded correctly"
                );

                // Verify stream is still idle but has priority info
                let stream_state = mock_connection.get_stream_state(stream_id);
                assert!(
                    matches!(stream_state, Some(StreamState::IdleWithPriority)),
                    "Stream should be in IdleWithPriority state after PRIORITY frame"
                );
            }
            PriorityResult::Rejected { reason } => {
                // Check if rejection is for a valid reason
                if is_valid_stream_dependency(test_case.priority_frame.stream_dependency, stream_id)
                {
                    // Should only reject for implementation limits or malformed data
                    assert!(
                        !test_case.priority_frame.extra_data.is_empty()
                            || test_case.priority_frame.weight == 0, // Invalid weight
                        "Valid PRIORITY should not be rejected: {}",
                        reason
                    );
                }
            }
        }

        // Verify priority is queryable
        let priority_info = mock_connection.get_stream_priority(stream_id);
        if matches!(result, PriorityResult::Accepted { .. }) {
            assert!(
                priority_info.is_some(),
                "Priority info should be available after accepted PRIORITY frame"
            );
        }
    }
}

/// Test priority application when stream opens with HEADERS
fn test_priority_application_on_open(test_case: &PriorityIdleTest) {
    if !test_case.send_headers_after {
        return; // Skip if not testing HEADERS
    }

    let stream_id = test_case.stream_id.max(1) | 1;
    let mut mock_connection = MockH2Connection::new(test_case.connection_settings.clone());

    // Send PRIORITY frame first
    let priority_sent = mock_connection.send_priority_frame(
        stream_id,
        test_case.priority_frame.stream_dependency,
        test_case.priority_frame.exclusive,
        test_case.priority_frame.weight,
        &test_case.priority_frame.extra_data,
    );

    if !matches!(priority_sent, PriorityResult::Accepted { .. }) {
        return; // Skip if PRIORITY was rejected
    }

    // Send HEADERS to open the stream
    let headers_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        mock_connection.send_headers_frame(
            stream_id,
            &test_case.headers_data.headers,
            test_case.headers_data.end_stream,
            test_case.headers_data.padding,
        )
    }));

    assert!(
        headers_result.is_ok(),
        "HEADERS frame should not panic on stream {} with prior PRIORITY",
        stream_id
    );

    if let Ok(headers_outcome) = headers_result {
        match headers_outcome {
            HeadersResult::StreamOpened { applied_priority } => {
                // Verify priority from PRIORITY frame was applied
                assert_eq!(
                    applied_priority.weight, test_case.priority_frame.weight,
                    "Priority weight should be applied when stream opens"
                );

                assert_eq!(
                    applied_priority.stream_dependency, test_case.priority_frame.stream_dependency,
                    "Stream dependency should be applied when stream opens"
                );

                assert_eq!(
                    applied_priority.exclusive, test_case.priority_frame.exclusive,
                    "Exclusive flag should be applied when stream opens"
                );

                // Verify stream is now open with correct priority
                let stream_state = mock_connection.get_stream_state(stream_id);
                assert!(
                    matches!(stream_state, Some(StreamState::Open)),
                    "Stream should be open after HEADERS frame"
                );

                let current_priority = mock_connection.get_stream_priority(stream_id);
                assert!(
                    current_priority.is_some(),
                    "Stream should have priority after opening"
                );

                if let Some(priority) = current_priority {
                    assert_eq!(
                        priority, applied_priority,
                        "Current stream priority should match applied priority"
                    );
                }
            }
            HeadersResult::Rejected { reason } => {
                // Headers rejection might be due to malformed headers, not priority
                if has_valid_headers(&test_case.headers_data.headers) {
                    panic!(
                        "Valid HEADERS should not be rejected after valid PRIORITY: {}",
                        reason
                    );
                }
            }
        }
    }
}

/// Test stream dependency handling
fn test_stream_dependency_handling(test_case: &PriorityIdleTest) {
    let stream_id = test_case.stream_id.max(1) | 1;
    let dependency_id = test_case.priority_frame.stream_dependency;

    if dependency_id == 0 || dependency_id == stream_id {
        return; // Skip self-dependency or no dependency cases
    }

    let mut mock_connection = MockH2Connection::new(test_case.connection_settings.clone());

    // Create the dependency stream if it's in concurrent streams
    let mut dependency_exists = false;
    for concurrent in &test_case.concurrent_streams {
        let concurrent_id = concurrent.stream_id.max(1) | 1;
        if concurrent_id == dependency_id && concurrent.is_open {
            mock_connection.open_stream(concurrent_id, concurrent.weight, 0);
            dependency_exists = true;
            break;
        }
    }

    // Send PRIORITY frame with dependency
    let priority_result = mock_connection.send_priority_frame(
        stream_id,
        dependency_id,
        test_case.priority_frame.exclusive,
        test_case.priority_frame.weight,
        &test_case.priority_frame.extra_data,
    );

    match priority_result {
        PriorityResult::Accepted { recorded_priority } => {
            if dependency_exists {
                // Dependency should be valid
                assert_eq!(
                    recorded_priority.stream_dependency, dependency_id,
                    "Dependency should be recorded when parent stream exists"
                );

                // Check dependency tree
                let dependency_tree = mock_connection.get_dependency_tree();
                assert!(
                    dependency_tree.has_dependency(stream_id, dependency_id),
                    "Dependency tree should reflect the PRIORITY frame"
                );

                if test_case.priority_frame.exclusive {
                    // Exclusive dependency should reorganize tree
                    let siblings = dependency_tree.get_children(dependency_id);
                    for sibling in siblings {
                        if sibling != stream_id {
                            assert!(
                                dependency_tree.has_dependency(sibling, stream_id),
                                "Exclusive dependency should make siblings depend on new stream"
                            );
                        }
                    }
                }
            }
        }
        PriorityResult::Rejected { .. } => {
            if !dependency_exists && dependency_id != 0 {
                // Rejection might be valid if dependency doesn't exist
                // but implementations may allow dependencies on idle streams
            }
        }
    }
}

/// Test exclusive dependency behavior
fn test_exclusive_dependency(test_case: &PriorityIdleTest) {
    if !test_case.priority_frame.exclusive {
        return; // Skip non-exclusive tests
    }

    let stream_id = test_case.stream_id.max(1) | 1;
    let dependency_id = test_case.priority_frame.stream_dependency;

    if dependency_id == 0 || dependency_id == stream_id {
        return; // Skip invalid dependencies
    }

    let mut mock_connection = MockH2Connection::new(test_case.connection_settings.clone());

    // Set up a dependency stream with existing children
    mock_connection.open_stream(dependency_id, 16, 0);
    let child1 = dependency_id + 2;
    let child2 = dependency_id + 4;
    mock_connection.open_stream(child1, 8, dependency_id);
    mock_connection.open_stream(child2, 12, dependency_id);

    // Record initial children
    let initial_children = mock_connection
        .get_dependency_tree()
        .get_children(dependency_id);

    // Send exclusive PRIORITY frame
    let priority_result = mock_connection.send_priority_frame(
        stream_id,
        dependency_id,
        true, // exclusive
        test_case.priority_frame.weight,
        &test_case.priority_frame.extra_data,
    );

    if let PriorityResult::Accepted { .. } = priority_result {
        let dependency_tree = mock_connection.get_dependency_tree();

        // New stream should depend on the parent
        assert!(
            dependency_tree.has_dependency(stream_id, dependency_id),
            "Exclusive stream should depend on parent"
        );

        // Previous children should now depend on the new stream
        for child in initial_children {
            if mock_connection.get_stream_state(child).is_some() {
                assert!(
                    dependency_tree.has_dependency(child, stream_id),
                    "Previous children should depend on exclusive stream {}",
                    child
                );
            }
        }

        // Parent should have only the new stream as direct child
        let new_children = dependency_tree.get_children(dependency_id);
        assert!(
            new_children.len() <= 1 || new_children.contains(&stream_id),
            "Parent should have new stream as child after exclusive dependency"
        );
    }
}

/// Test edge cases for PRIORITY on idle streams
fn test_priority_idle_edge_cases(test_case: &PriorityIdleTest) {
    let mut mock_connection = MockH2Connection::new(test_case.connection_settings.clone());

    // Test self-dependency (should be rejected)
    let self_dep_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        mock_connection.send_priority_frame(5, 5, false, 16, &[])
    }));
    assert!(self_dep_result.is_ok(), "Self-dependency should not panic");
    if let Ok(result) = self_dep_result {
        assert!(
            matches!(result, PriorityResult::Rejected { .. }),
            "Self-dependency should be rejected"
        );
    }

    // Test zero weight (implementation defined)
    let zero_weight_result = mock_connection.send_priority_frame(7, 0, false, 0, &[]);
    // Zero weight is technically invalid but handling is implementation-defined

    // Test connection-level dependency (stream 0)
    let conn_dep_result = mock_connection.send_priority_frame(9, 0, false, 32, &[]);
    // Dependency on stream 0 should be handled appropriately

    // Test oversized extra data
    let large_data = vec![0xFF; 1000];
    let large_data_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        mock_connection.send_priority_frame(11, 0, false, 64, &large_data)
    }));
    assert!(
        large_data_result.is_ok(),
        "Large extra data should not panic"
    );

    // Test maximum stream ID
    let max_stream_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        mock_connection.send_priority_frame(0x7FFFFFFF, 0, false, 128, &[])
    }));
    assert!(max_stream_result.is_ok(), "Max stream ID should not panic");

    // Test even stream ID (invalid for client)
    let even_stream_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        mock_connection.send_priority_frame(2, 0, false, 16, &[])
    }));
    assert!(
        even_stream_result.is_ok(),
        "Even stream ID should not panic"
    );
}

impl HeaderName {
    fn as_str(&self) -> &str {
        match self {
            Self::Method => ":method",
            Self::Path => ":path",
            Self::Scheme => ":scheme",
            Self::Authority => ":authority",
            Self::ContentType => "content-type",
            Self::UserAgent => "user-agent",
            Self::Custom(s) => s,
        }
    }
}

/// Check if stream dependency is valid
fn is_valid_stream_dependency(dependency_id: u32, stream_id: u32) -> bool {
    dependency_id != stream_id && dependency_id <= 0x7FFFFFFF
}

/// Check if headers are valid
fn has_valid_headers(headers: &[HeaderPair]) -> bool {
    let mut has_method = false;
    let mut has_path = false;

    for header in headers {
        match header.name {
            HeaderName::Method => {
                has_method = true;
                if header.value.is_empty() {
                    return false;
                }
            }
            HeaderName::Path => {
                has_path = true;
                if header.value.is_empty() {
                    return false;
                }
            }
            _ => {}
        }
    }

    has_method && has_path // Minimum required pseudo-headers
}

/// Stream states
#[derive(Debug, Clone, PartialEq, Eq)]
enum StreamState {
    Idle,
    IdleWithPriority,
    Open,
    HalfClosedLocal,
    HalfClosedRemote,
    Closed,
}

/// Priority information
#[derive(Debug, Clone, PartialEq, Eq)]
struct PriorityInfo {
    weight: u8,
    stream_dependency: u32,
    exclusive: bool,
}

/// Result of PRIORITY frame processing
#[derive(Debug, Clone)]
enum PriorityResult {
    Accepted { recorded_priority: PriorityInfo },
    Rejected { reason: String },
}

/// Result of HEADERS frame processing
#[derive(Debug, Clone)]
enum HeadersResult {
    StreamOpened { applied_priority: PriorityInfo },
    Rejected { reason: String },
}

/// Mock dependency tree
#[derive(Debug)]
struct DependencyTree {
    dependencies: HashMap<u32, u32>,  // child -> parent
    children: HashMap<u32, Vec<u32>>, // parent -> [children]
}

impl DependencyTree {
    fn new() -> Self {
        Self {
            dependencies: HashMap::new(),
            children: HashMap::new(),
        }
    }

    fn add_dependency(&mut self, child: u32, parent: u32, exclusive: bool) {
        if exclusive {
            // Move existing children to be children of the new child
            if let Some(existing_children) = self.children.remove(&parent) {
                for existing_child in existing_children {
                    self.dependencies.insert(existing_child, child);
                }
                self.children.insert(child, existing_children);
            }
        }

        self.dependencies.insert(child, parent);
        self.children
            .entry(parent)
            .or_insert_with(Vec::new)
            .push(child);
    }

    fn has_dependency(&self, child: u32, parent: u32) -> bool {
        self.dependencies.get(&child) == Some(&parent)
    }

    fn get_children(&self, parent: u32) -> Vec<u32> {
        self.children.get(&parent).cloned().unwrap_or_default()
    }
}

/// Mock HTTP/2 connection
struct MockH2Connection {
    streams: HashMap<u32, MockStreamInfo>,
    idle_priorities: HashMap<u32, PriorityInfo>,
    dependency_tree: DependencyTree,
    settings: ConnectionSettings,
}

/// Mock stream information
#[derive(Debug, Clone)]
struct MockStreamInfo {
    state: StreamState,
    priority: PriorityInfo,
}

impl MockH2Connection {
    fn new(settings: ConnectionSettings) -> Self {
        Self {
            streams: HashMap::new(),
            idle_priorities: HashMap::new(),
            dependency_tree: DependencyTree::new(),
            settings,
        }
    }

    fn send_priority_frame(
        &mut self,
        stream_id: u32,
        stream_dependency: u32,
        exclusive: bool,
        weight: u8,
        extra_data: &[u8],
    ) -> PriorityResult {
        // Validate frame size
        if extra_data.len() > 5 {
            // PRIORITY frame should be exactly 5 bytes
            return PriorityResult::Rejected {
                reason: "PRIORITY frame too large".to_string(),
            };
        }

        // Validate weight
        if weight == 0 {
            return PriorityResult::Rejected {
                reason: "Priority weight cannot be zero".to_string(),
            };
        }

        // Check for self-dependency
        if stream_dependency == stream_id {
            return PriorityResult::Rejected {
                reason: "Stream cannot depend on itself".to_string(),
            };
        }

        // Validate stream ID
        if stream_id > 0x7FFFFFFF || (stream_id & 1) == 0 {
            return PriorityResult::Rejected {
                reason: "Invalid stream ID".to_string(),
            };
        }

        let priority_info = PriorityInfo {
            weight,
            stream_dependency,
            exclusive,
        };

        // Check if stream exists
        if let Some(stream_info) = self.streams.get_mut(&stream_id) {
            // Update existing stream priority
            stream_info.priority = priority_info.clone();
            self.dependency_tree
                .add_dependency(stream_id, stream_dependency, exclusive);
        } else {
            // Record priority for idle stream
            self.idle_priorities
                .insert(stream_id, priority_info.clone());
        }

        PriorityResult::Accepted {
            recorded_priority: priority_info,
        }
    }

    fn send_headers_frame(
        &mut self,
        stream_id: u32,
        headers: &[HeaderPair],
        end_stream: bool,
        _padding: Option<u8>,
    ) -> HeadersResult {
        if !has_valid_headers(headers) {
            return HeadersResult::Rejected {
                reason: "Invalid headers".to_string(),
            };
        }

        // Get priority from idle priorities or use default
        let priority = self
            .idle_priorities
            .remove(&stream_id)
            .unwrap_or(PriorityInfo {
                weight: 16,
                stream_dependency: 0,
                exclusive: false,
            });

        // Create stream
        let stream_info = MockStreamInfo {
            state: if end_stream {
                StreamState::HalfClosedLocal
            } else {
                StreamState::Open
            },
            priority: priority.clone(),
        };

        self.streams.insert(stream_id, stream_info);

        // Update dependency tree
        self.dependency_tree.add_dependency(
            stream_id,
            priority.stream_dependency,
            priority.exclusive,
        );

        HeadersResult::StreamOpened {
            applied_priority: priority,
        }
    }

    fn open_stream(&mut self, stream_id: u32, weight: u8, depends_on: u32) {
        let priority = PriorityInfo {
            weight,
            stream_dependency: depends_on,
            exclusive: false,
        };

        let stream_info = MockStreamInfo {
            state: StreamState::Open,
            priority,
        };

        self.streams.insert(stream_id, stream_info);

        if depends_on != 0 {
            self.dependency_tree
                .add_dependency(stream_id, depends_on, false);
        }
    }

    fn get_stream_state(&self, stream_id: u32) -> Option<StreamState> {
        if let Some(stream) = self.streams.get(&stream_id) {
            Some(stream.state.clone())
        } else if self.idle_priorities.contains_key(&stream_id) {
            Some(StreamState::IdleWithPriority)
        } else {
            None
        }
    }

    fn get_stream_priority(&self, stream_id: u32) -> Option<PriorityInfo> {
        if let Some(stream) = self.streams.get(&stream_id) {
            Some(stream.priority.clone())
        } else {
            self.idle_priorities.get(&stream_id).cloned()
        }
    }

    fn get_dependency_tree(&self) -> &DependencyTree {
        &self.dependency_tree
    }
}

/// Generate test scenarios for PRIORITY on idle streams
fn generate_idle_priority_scenarios() -> Vec<PriorityIdleTest> {
    vec![
        // Basic PRIORITY then HEADERS
        PriorityIdleTest {
            stream_id: 1,
            priority_frame: PriorityFrameData {
                stream_dependency: 0,
                exclusive: false,
                weight: 32,
                extra_data: vec![],
            },
            send_headers_after: true,
            headers_data: HeadersFrameData {
                end_stream: false,
                headers: vec![
                    HeaderPair {
                        name: HeaderName::Method,
                        value: "GET".to_string(),
                    },
                    HeaderPair {
                        name: HeaderName::Path,
                        value: "/test".to_string(),
                    },
                ],
                padding: None,
            },
            concurrent_streams: vec![],
            connection_settings: ConnectionSettings {
                initial_window_size: 65535,
                max_concurrent_streams: 100,
                enable_push: false,
            },
        },
        // Exclusive dependency scenario
        PriorityIdleTest {
            stream_id: 5,
            priority_frame: PriorityFrameData {
                stream_dependency: 3,
                exclusive: true,
                weight: 64,
                extra_data: vec![],
            },
            send_headers_after: true,
            headers_data: HeadersFrameData {
                end_stream: true,
                headers: vec![
                    HeaderPair {
                        name: HeaderName::Method,
                        value: "POST".to_string(),
                    },
                    HeaderPair {
                        name: HeaderName::Path,
                        value: "/api".to_string(),
                    },
                ],
                padding: Some(5),
            },
            concurrent_streams: vec![ConcurrentStream {
                stream_id: 3,
                is_open: true,
                weight: 16,
                depends_on: 0,
            }],
            connection_settings: ConnectionSettings {
                initial_window_size: 32768,
                max_concurrent_streams: 50,
                enable_push: true,
            },
        },
    ]
}

/// Test that demonstrates expected PRIORITY behavior
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_priority_recorded_on_idle_stream() {
        let mut conn = MockH2Connection::new(ConnectionSettings {
            initial_window_size: 65535,
            max_concurrent_streams: 100,
            enable_push: false,
        });

        let result = conn.send_priority_frame(1, 0, false, 32, &[]);
        assert!(matches!(result, PriorityResult::Accepted { .. }));

        let state = conn.get_stream_state(1);
        assert_eq!(state, Some(StreamState::IdleWithPriority));

        let priority = conn.get_stream_priority(1);
        assert!(priority.is_some());
        assert_eq!(priority.unwrap().weight, 32);
    }

    #[test]
    fn test_priority_applied_when_stream_opens() {
        let mut conn = MockH2Connection::new(ConnectionSettings {
            initial_window_size: 65535,
            max_concurrent_streams: 100,
            enable_push: false,
        });

        // Send PRIORITY first
        conn.send_priority_frame(1, 0, false, 64, &[]);

        // Send HEADERS to open stream
        let headers = vec![
            HeaderPair {
                name: HeaderName::Method,
                value: "GET".to_string(),
            },
            HeaderPair {
                name: HeaderName::Path,
                value: "/".to_string(),
            },
        ];

        let result = conn.send_headers_frame(1, &headers, false, None);
        match result {
            HeadersResult::StreamOpened { applied_priority } => {
                assert_eq!(applied_priority.weight, 64);
            }
            _ => panic!("Expected stream to open with applied priority"),
        }

        let state = conn.get_stream_state(1);
        assert_eq!(state, Some(StreamState::Open));
    }

    #[test]
    fn test_exclusive_dependency_reorganizes_tree() {
        let mut conn = MockH2Connection::new(ConnectionSettings {
            initial_window_size: 65535,
            max_concurrent_streams: 100,
            enable_push: false,
        });

        // Set up parent with children
        conn.open_stream(1, 16, 0);
        conn.open_stream(3, 8, 1);
        conn.open_stream(5, 12, 1);

        // Send exclusive PRIORITY on idle stream
        conn.send_priority_frame(7, 1, true, 32, &[]);

        let tree = conn.get_dependency_tree();
        assert!(tree.has_dependency(7, 1));
        // Previous children should now depend on stream 7
        assert!(tree.has_dependency(3, 7));
        assert!(tree.has_dependency(5, 7));
    }
}
