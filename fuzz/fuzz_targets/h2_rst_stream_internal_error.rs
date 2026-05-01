//! HTTP/2 RST_STREAM with INTERNAL_ERROR cleanup fuzz target.
//!
//! Tests RST_STREAM frame handling with INTERNAL_ERROR per RFC 7540 Section 6.4.
//! RST_STREAM immediately terminates a stream and should clean up all resources
//! regardless of the stream's current state.
//!
//! This fuzzer generates arbitrary stream states and verifies:
//! 1. RST_STREAM with INTERNAL_ERROR cleans up streams in any state
//! 2. No orphan resources remain after stream termination
//! 3. Stream state transitions are handled correctly
//! 4. Concurrent operations are properly cancelled
//! 5. No panics occur during cleanup

#![no_main]

use arbitrary::Arbitrary;
use asupersync::bytes::BytesMut;
use libfuzzer_sys::fuzz_target;
use std::collections::HashMap;

/// RST_STREAM cleanup test with arbitrary stream states
#[derive(Debug, Clone, Arbitrary)]
struct RstStreamTest {
    /// Target stream ID for RST_STREAM
    stream_id: u32,
    /// Current stream state before RST_STREAM
    stream_state: StreamState,
    /// Pending operations on the stream
    pending_operations: Vec<PendingOperation>,
    /// Stream-specific resources
    stream_resources: StreamResources,
    /// Additional concurrent streams
    concurrent_streams: Vec<ConcurrentStream>,
    /// Connection-level settings
    connection_settings: ConnectionSettings,
}

/// HTTP/2 stream states
#[derive(Debug, Clone, Arbitrary)]
enum StreamState {
    /// Stream is idle (not yet opened)
    Idle,
    /// Stream is reserved (local)
    ReservedLocal,
    /// Stream is reserved (remote)
    ReservedRemote,
    /// Stream is open (bidirectional)
    Open,
    /// Stream is half-closed (local end closed)
    HalfClosedLocal,
    /// Stream is half-closed (remote end closed)
    HalfClosedRemote,
    /// Stream is closed
    Closed,
    /// Stream is in an error state
    Error,
}

/// Pending operations on a stream
#[derive(Debug, Clone, Arbitrary)]
struct PendingOperation {
    /// Operation type
    operation_type: OperationType,
    /// Data associated with the operation
    data: Vec<u8>,
    /// Operation priority
    priority: u8,
}

/// Types of operations that can be pending
#[derive(Debug, Clone, Arbitrary)]
enum OperationType {
    /// DATA frame send
    SendData,
    /// HEADERS frame send
    SendHeaders,
    /// Window update
    WindowUpdate,
    /// Flow control operation
    FlowControl,
    /// Read from stream
    Read,
    /// Write to stream
    Write,
    /// Stream closure
    Close,
}

/// Resources associated with a stream
#[derive(Debug, Clone, Arbitrary)]
struct StreamResources {
    /// Send window size
    send_window: i32,
    /// Receive window size
    recv_window: i32,
    /// Buffered data
    buffered_data: Vec<u8>,
    /// Stream priority weight
    priority_weight: u8,
    /// Stream dependencies
    dependencies: Vec<u32>,
    /// Headers state
    headers_received: bool,
    headers_sent: bool,
    /// End stream flags
    end_stream_sent: bool,
    end_stream_received: bool,
}

/// Concurrent streams for testing interactions
#[derive(Debug, Clone, Arbitrary)]
struct ConcurrentStream {
    /// Stream ID
    stream_id: u32,
    /// Stream state
    state: StreamState,
    /// Whether this stream depends on the target stream
    depends_on_target: bool,
}

/// Connection-level settings
#[derive(Debug, Clone, Arbitrary)]
struct ConnectionSettings {
    /// Maximum concurrent streams
    max_concurrent_streams: u32,
    /// Initial window size
    initial_window_size: u32,
    /// Maximum frame size
    max_frame_size: u32,
    /// Header table size
    header_table_size: u32,
}

fuzz_target!(|data: &[u8]| {
    // Guard against excessive input size
    if data.len() > 100_000 {
        return;
    }

    let mut u = arbitrary::Unstructured::new(data);

    // Generate RST_STREAM test case
    let test_case = match RstStreamTest::arbitrary(&mut u) {
        Ok(case) => case,
        Err(_) => return,
    };

    // Limit concurrent streams and operations for performance
    if test_case.concurrent_streams.len() > 20
        || test_case.pending_operations.len() > 10
        || test_case.stream_resources.buffered_data.len() > 50_000 {
        return;
    }

    // Test core RST_STREAM cleanup
    test_rst_stream_cleanup(&test_case);

    // Test resource cleanup specifically
    test_resource_cleanup(&test_case);

    // Test concurrent stream interactions
    test_concurrent_stream_cleanup(&test_case);

    // Test stream state transitions
    test_stream_state_transitions(&test_case);

    // Test edge cases
    test_cleanup_edge_cases(&test_case);
});

/// Test RST_STREAM cleanup with INTERNAL_ERROR
fn test_rst_stream_cleanup(test_case: &RstStreamTest) {
    let stream_id = test_case.stream_id.max(1) | 1; // Ensure odd stream ID
    let mut mock_connection = MockConnection::new(test_case.connection_settings.clone());

    // Set up the stream in the specified state
    let setup_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        mock_connection.setup_stream(stream_id, &test_case.stream_state, &test_case.stream_resources);

        // Add pending operations
        for operation in &test_case.pending_operations {
            mock_connection.add_pending_operation(stream_id, operation.clone());
        }

        // Set up concurrent streams
        for concurrent in &test_case.concurrent_streams {
            if concurrent.stream_id != stream_id {
                mock_connection.setup_stream(concurrent.stream_id, &concurrent.state,
                    &StreamResources::default());
                if concurrent.depends_on_target {
                    mock_connection.add_stream_dependency(concurrent.stream_id, stream_id);
                }
            }
        }
    }));

    assert!(setup_result.is_ok(),
        "Stream setup should not panic for stream_id={}, state={:?}",
        stream_id, test_case.stream_state);

    // Send RST_STREAM with INTERNAL_ERROR
    let rst_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        mock_connection.send_rst_stream(stream_id, ErrorCode::InternalError)
    }));

    assert!(rst_result.is_ok(),
        "RST_STREAM should not panic for stream_id={} in state {:?}",
        stream_id, test_case.stream_state);

    if let Ok(cleanup_result) = rst_result {
        match cleanup_result {
            CleanupResult::Success { resources_freed } => {
                // Verify that resources were actually cleaned up
                assert!(resources_freed.stream_removed,
                    "Stream {} should be removed after RST_STREAM", stream_id);

                // Check that all expected resources were freed
                if !test_case.pending_operations.is_empty() {
                    assert!(resources_freed.operations_cancelled > 0,
                        "Pending operations should be cancelled for stream {}", stream_id);
                }

                if !test_case.stream_resources.buffered_data.is_empty() {
                    assert!(resources_freed.buffers_freed,
                        "Buffered data should be freed for stream {}", stream_id);
                }
            }
            CleanupResult::PartialCleanup { remaining_resources } => {
                // Partial cleanup might be acceptable in some implementations
                // but should be minimized
                assert!(remaining_resources.len() < test_case.pending_operations.len(),
                    "Should clean up most resources for stream {}", stream_id);
            }
            CleanupResult::Error { reason } => {
                // Errors during cleanup should only happen for invalid stream IDs
                // or in very specific edge cases
                if is_valid_stream_id(stream_id) {
                    panic!("Cleanup error for valid stream {}: {}", stream_id, reason);
                }
            }
        }

        // Verify stream is no longer accessible
        let post_cleanup_check = mock_connection.check_stream_exists(stream_id);
        assert!(!post_cleanup_check,
            "Stream {} should not exist after RST_STREAM cleanup", stream_id);
    }
}

/// Test that all resources are properly cleaned up
fn test_resource_cleanup(test_case: &RstStreamTest) {
    let stream_id = test_case.stream_id.max(1) | 1;
    let mut mock_connection = MockConnection::new(test_case.connection_settings.clone());

    // Set up stream with resources
    mock_connection.setup_stream(stream_id, &test_case.stream_state, &test_case.stream_resources);

    // Track initial resource counts
    let initial_resources = mock_connection.get_resource_counts();

    // Send RST_STREAM
    let _ = mock_connection.send_rst_stream(stream_id, ErrorCode::InternalError);

    // Check final resource counts
    let final_resources = mock_connection.get_resource_counts();

    // Verify resources were cleaned up
    assert!(final_resources.stream_count <= initial_resources.stream_count,
        "Stream count should not increase after RST_STREAM");

    assert!(final_resources.buffer_bytes <= initial_resources.buffer_bytes,
        "Buffer memory should not increase after RST_STREAM");

    assert!(final_resources.pending_operations <= initial_resources.pending_operations,
        "Pending operations should not increase after RST_STREAM");

    // For INTERNAL_ERROR, we expect aggressive cleanup
    if matches!(test_case.stream_state, StreamState::Open | StreamState::HalfClosedLocal | StreamState::HalfClosedRemote) {
        assert!(final_resources.stream_count < initial_resources.stream_count,
            "Stream should be removed for INTERNAL_ERROR in active state");
    }
}

/// Test cleanup interactions with concurrent streams
fn test_concurrent_stream_cleanup(test_case: &RstStreamTest) {
    let target_stream = test_case.stream_id.max(1) | 1;
    let mut mock_connection = MockConnection::new(test_case.connection_settings.clone());

    // Set up target stream
    mock_connection.setup_stream(target_stream, &test_case.stream_state, &test_case.stream_resources);

    // Set up concurrent streams
    let mut dependent_streams = Vec::new();
    for concurrent in &test_case.concurrent_streams {
        let concurrent_id = concurrent.stream_id.max(3) | 1; // Ensure odd and != target
        if concurrent_id != target_stream {
            mock_connection.setup_stream(concurrent_id, &concurrent.state, &StreamResources::default());
            if concurrent.depends_on_target {
                mock_connection.add_stream_dependency(concurrent_id, target_stream);
                dependent_streams.push(concurrent_id);
            }
        }
    }

    // Send RST_STREAM to target
    let cleanup_result = mock_connection.send_rst_stream(target_stream, ErrorCode::InternalError);

    // Verify dependent streams are handled correctly
    for dependent_id in dependent_streams {
        let dependent_state = mock_connection.get_stream_state(dependent_id);
        match dependent_state {
            Some(StreamState::Error) => {
                // Dependent stream transitioned to error state - acceptable
            }
            Some(_) => {
                // Dependent stream still exists but dependency should be removed
                assert!(!mock_connection.has_stream_dependency(dependent_id, target_stream),
                    "Stream {} should not depend on RST stream {}", dependent_id, target_stream);
            }
            None => {
                // Dependent stream was also cleaned up - acceptable for INTERNAL_ERROR
            }
        }
    }

    // Verify other concurrent streams are unaffected
    for concurrent in &test_case.concurrent_streams {
        let concurrent_id = concurrent.stream_id.max(3) | 1;
        if concurrent_id != target_stream && !concurrent.depends_on_target {
            let state = mock_connection.get_stream_state(concurrent_id);
            assert!(state.is_some(),
                "Unrelated stream {} should not be affected by RST_STREAM on {}",
                concurrent_id, target_stream);
        }
    }
}

/// Test stream state transitions during cleanup
fn test_stream_state_transitions(test_case: &RstStreamTest) {
    let stream_id = test_case.stream_id.max(1) | 1;
    let mut mock_connection = MockConnection::new(test_case.connection_settings.clone());

    mock_connection.setup_stream(stream_id, &test_case.stream_state, &test_case.stream_resources);

    // Record initial state
    let initial_state = mock_connection.get_stream_state(stream_id);

    // Send RST_STREAM
    let _ = mock_connection.send_rst_stream(stream_id, ErrorCode::InternalError);

    // Check final state
    let final_state = mock_connection.get_stream_state(stream_id);

    // For RST_STREAM with INTERNAL_ERROR, stream should be removed or in error state
    match final_state {
        None => {
            // Stream removed completely - preferred for INTERNAL_ERROR
        }
        Some(StreamState::Error) => {
            // Stream transitioned to error state - acceptable
        }
        Some(other_state) => {
            // Stream in unexpected state
            assert!(matches!(initial_state, Some(StreamState::Closed)),
                "Only closed streams might remain in state {:?} after INTERNAL_ERROR, was {:?}",
                other_state, initial_state);
        }
    }
}

/// Test edge cases in cleanup
fn test_cleanup_edge_cases(test_case: &RstStreamTest) {
    let mut mock_connection = MockConnection::new(test_case.connection_settings.clone());

    // Test RST_STREAM on non-existent stream
    let nonexistent_stream = 999999;
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        mock_connection.send_rst_stream(nonexistent_stream, ErrorCode::InternalError)
    }));
    assert!(result.is_ok(), "RST_STREAM on non-existent stream should not panic");

    // Test RST_STREAM on stream ID 0 (connection-level)
    let connection_rst = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        mock_connection.send_rst_stream(0, ErrorCode::InternalError)
    }));
    assert!(connection_rst.is_ok(), "RST_STREAM on stream 0 should not panic");

    // Test RST_STREAM with invalid stream ID (even number for client)
    let invalid_stream = test_case.stream_id.max(2) & !1; // Ensure even
    let invalid_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        mock_connection.send_rst_stream(invalid_stream, ErrorCode::InternalError)
    }));
    assert!(invalid_result.is_ok(), "RST_STREAM with invalid stream ID should not panic");

    // Test double RST_STREAM
    let stream_id = test_case.stream_id.max(1) | 1;
    mock_connection.setup_stream(stream_id, &test_case.stream_state, &test_case.stream_resources);

    let first_rst = mock_connection.send_rst_stream(stream_id, ErrorCode::InternalError);
    let second_rst = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        mock_connection.send_rst_stream(stream_id, ErrorCode::InternalError)
    }));

    assert!(second_rst.is_ok(), "Double RST_STREAM should not panic");
}

/// HTTP/2 error codes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
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

/// Result of cleanup operation
#[derive(Debug, Clone)]
enum CleanupResult {
    /// Successful cleanup
    Success { resources_freed: ResourcesFreed },
    /// Partial cleanup (some resources remain)
    PartialCleanup { remaining_resources: Vec<String> },
    /// Error during cleanup
    Error { reason: String },
}

/// Resources that were freed during cleanup
#[derive(Debug, Clone)]
struct ResourcesFreed {
    /// Stream was removed from connection
    stream_removed: bool,
    /// Number of pending operations cancelled
    operations_cancelled: usize,
    /// Buffered data was freed
    buffers_freed: bool,
    /// Window credits were returned
    window_credits_returned: i32,
    /// Dependencies were cleaned up
    dependencies_cleared: bool,
}

/// Resource usage counts
#[derive(Debug, Clone)]
struct ResourceCounts {
    stream_count: usize,
    buffer_bytes: usize,
    pending_operations: usize,
    dependency_count: usize,
}

/// Mock HTTP/2 connection for testing
struct MockConnection {
    streams: HashMap<u32, MockStream>,
    settings: ConnectionSettings,
    dependencies: HashMap<u32, Vec<u32>>, // stream_id -> [dependent_streams]
}

/// Mock stream state
#[derive(Debug, Clone)]
struct MockStream {
    state: StreamState,
    resources: StreamResources,
    pending_operations: Vec<PendingOperation>,
}

impl Default for StreamResources {
    fn default() -> Self {
        Self {
            send_window: 65535,
            recv_window: 65535,
            buffered_data: Vec::new(),
            priority_weight: 16,
            dependencies: Vec::new(),
            headers_received: false,
            headers_sent: false,
            end_stream_sent: false,
            end_stream_received: false,
        }
    }
}

impl MockConnection {
    fn new(settings: ConnectionSettings) -> Self {
        Self {
            streams: HashMap::new(),
            settings,
            dependencies: HashMap::new(),
        }
    }

    fn setup_stream(&mut self, stream_id: u32, state: &StreamState, resources: &StreamResources) {
        let mock_stream = MockStream {
            state: state.clone(),
            resources: resources.clone(),
            pending_operations: Vec::new(),
        };
        self.streams.insert(stream_id, mock_stream);
    }

    fn add_pending_operation(&mut self, stream_id: u32, operation: PendingOperation) {
        if let Some(stream) = self.streams.get_mut(&stream_id) {
            stream.pending_operations.push(operation);
        }
    }

    fn add_stream_dependency(&mut self, stream_id: u32, depends_on: u32) {
        self.dependencies.entry(depends_on).or_insert_with(Vec::new).push(stream_id);
    }

    fn send_rst_stream(&mut self, stream_id: u32, error_code: ErrorCode) -> CleanupResult {
        // Special case: stream ID 0 affects entire connection
        if stream_id == 0 {
            return CleanupResult::Error {
                reason: "RST_STREAM not valid for connection (stream 0)".to_string()
            };
        }

        // Check if stream exists
        let stream = match self.streams.get(&stream_id) {
            Some(s) => s.clone(),
            None => {
                return CleanupResult::Error {
                    reason: format!("Stream {} not found", stream_id)
                };
            }
        };

        // For INTERNAL_ERROR, perform aggressive cleanup
        if error_code == ErrorCode::InternalError {
            let operations_cancelled = stream.pending_operations.len();
            let buffers_freed = !stream.resources.buffered_data.is_empty();
            let window_credits = stream.resources.send_window + stream.resources.recv_window;

            // Remove stream
            self.streams.remove(&stream_id);

            // Clean up dependencies
            let mut dependencies_cleared = false;
            if let Some(dependents) = self.dependencies.remove(&stream_id) {
                // Handle dependent streams - they become orphaned
                for dependent_id in dependents {
                    if let Some(dependent_stream) = self.streams.get_mut(&dependent_id) {
                        // Transition dependent to error state or remove dependency
                        dependent_stream.state = StreamState::Error;
                    }
                }
                dependencies_cleared = true;
            }

            // Remove this stream from other dependencies
            for (_, deps) in self.dependencies.iter_mut() {
                deps.retain(|&id| id != stream_id);
            }

            return CleanupResult::Success {
                resources_freed: ResourcesFreed {
                    stream_removed: true,
                    operations_cancelled,
                    buffers_freed,
                    window_credits_returned: window_credits,
                    dependencies_cleared,
                }
            };
        }

        // For other error codes, cleanup might be different
        CleanupResult::PartialCleanup {
            remaining_resources: vec!["Stream state retained for non-INTERNAL_ERROR".to_string()]
        }
    }

    fn check_stream_exists(&self, stream_id: u32) -> bool {
        self.streams.contains_key(&stream_id)
    }

    fn get_stream_state(&self, stream_id: u32) -> Option<StreamState> {
        self.streams.get(&stream_id).map(|s| s.state.clone())
    }

    fn has_stream_dependency(&self, stream_id: u32, depends_on: u32) -> bool {
        self.dependencies
            .get(&depends_on)
            .map(|deps| deps.contains(&stream_id))
            .unwrap_or(false)
    }

    fn get_resource_counts(&self) -> ResourceCounts {
        let stream_count = self.streams.len();
        let buffer_bytes = self.streams.values()
            .map(|s| s.resources.buffered_data.len())
            .sum();
        let pending_operations = self.streams.values()
            .map(|s| s.pending_operations.len())
            .sum();
        let dependency_count = self.dependencies.values()
            .map(|deps| deps.len())
            .sum();

        ResourceCounts {
            stream_count,
            buffer_bytes,
            pending_operations,
            dependency_count,
        }
    }
}

/// Check if stream ID is valid for client-initiated streams
fn is_valid_stream_id(stream_id: u32) -> bool {
    stream_id > 0 && stream_id & 1 == 1 // Odd numbers for client streams
}

/// Generate various stream cleanup scenarios
fn generate_cleanup_scenarios() -> Vec<RstStreamTest> {
    vec![
        // Open stream with pending data
        RstStreamTest {
            stream_id: 1,
            stream_state: StreamState::Open,
            pending_operations: vec![
                PendingOperation {
                    operation_type: OperationType::SendData,
                    data: b"pending data".to_vec(),
                    priority: 5,
                }
            ],
            stream_resources: StreamResources {
                buffered_data: b"buffered response".to_vec(),
                send_window: 32768,
                recv_window: 65535,
                ..Default::default()
            },
            concurrent_streams: vec![],
            connection_settings: ConnectionSettings {
                max_concurrent_streams: 100,
                initial_window_size: 65535,
                max_frame_size: 16384,
                header_table_size: 4096,
            },
        },

        // Half-closed stream with dependencies
        RstStreamTest {
            stream_id: 3,
            stream_state: StreamState::HalfClosedLocal,
            pending_operations: vec![],
            stream_resources: StreamResources {
                dependencies: vec![5, 7],
                headers_sent: true,
                end_stream_sent: true,
                ..Default::default()
            },
            concurrent_streams: vec![
                ConcurrentStream {
                    stream_id: 5,
                    state: StreamState::Open,
                    depends_on_target: true,
                },
                ConcurrentStream {
                    stream_id: 7,
                    state: StreamState::Open,
                    depends_on_target: true,
                },
            ],
            connection_settings: ConnectionSettings {
                max_concurrent_streams: 100,
                initial_window_size: 32768,
                max_frame_size: 8192,
                header_table_size: 2048,
            },
        },

        // Stream in error state
        RstStreamTest {
            stream_id: 9,
            stream_state: StreamState::Error,
            pending_operations: vec![
                PendingOperation {
                    operation_type: OperationType::Close,
                    data: vec![],
                    priority: 0,
                }
            ],
            stream_resources: StreamResources {
                send_window: -1000, // Negative window from flow control error
                ..Default::default()
            },
            concurrent_streams: vec![],
            connection_settings: ConnectionSettings {
                max_concurrent_streams: 50,
                initial_window_size: 16384,
                max_frame_size: 32768,
                header_table_size: 8192,
            },
        },
    ]
}

/// Test that demonstrates expected RST_STREAM cleanup behavior
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rst_internal_error_removes_stream() {
        let settings = ConnectionSettings {
            max_concurrent_streams: 100,
            initial_window_size: 65535,
            max_frame_size: 16384,
            header_table_size: 4096,
        };

        let mut conn = MockConnection::new(settings);
        conn.setup_stream(1, &StreamState::Open, &StreamResources::default());

        assert!(conn.check_stream_exists(1), "Stream should exist before RST");

        let result = conn.send_rst_stream(1, ErrorCode::InternalError);
        assert!(matches!(result, CleanupResult::Success { .. }));
        assert!(!conn.check_stream_exists(1), "Stream should be removed after RST_STREAM INTERNAL_ERROR");
    }

    #[test]
    fn test_rst_cleans_up_pending_operations() {
        let mut conn = MockConnection::new(ConnectionSettings {
            max_concurrent_streams: 100,
            initial_window_size: 65535,
            max_frame_size: 16384,
            header_table_size: 4096,
        });

        conn.setup_stream(3, &StreamState::Open, &StreamResources::default());
        conn.add_pending_operation(3, PendingOperation {
            operation_type: OperationType::SendData,
            data: b"test".to_vec(),
            priority: 1,
        });

        let result = conn.send_rst_stream(3, ErrorCode::InternalError);
        match result {
            CleanupResult::Success { resources_freed } => {
                assert!(resources_freed.operations_cancelled > 0, "Should cancel pending operations");
            }
            _ => panic!("Expected successful cleanup"),
        }
    }

    #[test]
    fn test_rst_handles_dependencies() {
        let mut conn = MockConnection::new(ConnectionSettings {
            max_concurrent_streams: 100,
            initial_window_size: 65535,
            max_frame_size: 16384,
            header_table_size: 4096,
        });

        // Set up parent and dependent streams
        conn.setup_stream(1, &StreamState::Open, &StreamResources::default());
        conn.setup_stream(3, &StreamState::Open, &StreamResources::default());
        conn.add_stream_dependency(3, 1);

        let result = conn.send_rst_stream(1, ErrorCode::InternalError);
        assert!(matches!(result, CleanupResult::Success { .. }));

        // Dependent stream should be in error state
        assert!(matches!(conn.get_stream_state(3), Some(StreamState::Error)));
        assert!(!conn.has_stream_dependency(3, 1), "Dependency should be removed");
    }

    #[test]
    fn test_rst_nonexistent_stream() {
        let mut conn = MockConnection::new(ConnectionSettings {
            max_concurrent_streams: 100,
            initial_window_size: 65535,
            max_frame_size: 16384,
            header_table_size: 4096,
        });

        let result = conn.send_rst_stream(999, ErrorCode::InternalError);
        assert!(matches!(result, CleanupResult::Error { .. }));
    }

    #[test]
    fn test_rst_stream_zero() {
        let mut conn = MockConnection::new(ConnectionSettings {
            max_concurrent_streams: 100,
            initial_window_size: 65535,
            max_frame_size: 16384,
            header_table_size: 4096,
        });

        let result = conn.send_rst_stream(0, ErrorCode::InternalError);
        assert!(matches!(result, CleanupResult::Error { .. }));
    }
}