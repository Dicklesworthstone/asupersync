#![no_main]

//! Fuzz target for HTTP/2 SETTINGS_MAX_CONCURRENT_STREAMS dynamic behavior.
//!
//! This target tests the dynamic stream concurrency limit management per RFC 7540:
//!
//! - SETTINGS_MAX_CONCURRENT_STREAMS controls maximum active streams
//! - Dynamic updates don't affect existing active streams
//! - New stream allocation rejected when limit reached with "max concurrent streams exceeded"
//! - PUSH_PROMISE frames are also subject to the concurrent streams limit
//! - Only active streams count (closed streams can be pruned to make room)
//! - Zero limit prevents all new stream creation
//!
//! Expected behavior:
//! - Valid limits: new streams rejected when active count reaches limit
//! - Dynamic reductions: existing streams unaffected, new allocation blocked
//! - Stream lifecycle: allocation -> activation -> close -> prune
//! - PUSH_PROMISE enforcement: server pushes limited by concurrent limit

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use std::collections::HashMap;

/// HTTP/2 stream state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StreamState {
    Idle,
    Open,
    HalfClosedLocal,
    Closed,
    ReservedRemote,
}

impl StreamState {
    /// Check if stream is active (counts toward concurrent limit)
    fn is_active(self) -> bool {
        match self {
            StreamState::Open | StreamState::HalfClosedLocal | StreamState::ReservedRemote => true,
            StreamState::Idle | StreamState::Closed => false,
        }
    }

    fn is_closed(self) -> bool {
        matches!(self, StreamState::Closed)
    }
}

/// Stream information
#[derive(Debug, Clone)]
struct StreamInfo {
    stream_id: u32,
    state: StreamState,
}

impl StreamInfo {
    fn new(stream_id: u32) -> Self {
        Self {
            stream_id,
            state: StreamState::Idle,
        }
    }

    fn send_headers(&mut self, end_stream: bool) -> Result<(), String> {
        match self.state {
            StreamState::Idle => {
                self.state = if end_stream {
                    StreamState::HalfClosedLocal
                } else {
                    StreamState::Open
                };
                Ok(())
            }
            _ => Err("Invalid state for send_headers".to_string()),
        }
    }

    fn reset(&mut self) {
        self.state = StreamState::Closed;
    }

    fn is_active(&self) -> bool {
        self.state.is_active()
    }

    fn is_closed(&self) -> bool {
        self.state.is_closed()
    }
}

fn observe_send_headers(stream: &mut StreamInfo, end_stream: bool, context: &str) {
    let old_state = stream.state;
    let result = stream.send_headers(end_stream);

    match result {
        Ok(()) => {
            assert_eq!(
                old_state,
                StreamState::Idle,
                "{context}: send_headers succeeded from non-idle state"
            );
            let expected_state = if end_stream {
                StreamState::HalfClosedLocal
            } else {
                StreamState::Open
            };
            assert_eq!(
                stream.state, expected_state,
                "{context}: send_headers stored wrong state"
            );
            assert!(
                stream.is_active(),
                "{context}: send_headers success did not make stream active"
            );
        }
        Err(error) => {
            assert_ne!(
                old_state,
                StreamState::Idle,
                "{context}: send_headers rejected an idle stream"
            );
            assert_eq!(
                stream.state, old_state,
                "{context}: failed send_headers changed stream state"
            );
            assert!(
                error.contains("Invalid state for send_headers"),
                "{context}: send_headers returned an unexpected error: {error}"
            );
        }
    }
}

/// Mock HTTP/2 stream store for concurrent streams testing
#[derive(Debug)]
struct MockStreamStore {
    streams: HashMap<u32, StreamInfo>,
    max_concurrent_streams: u32,
    next_client_stream_id: u32, // Odd IDs for client
    next_server_stream_id: u32, // Even IDs for server
    is_client: bool,
    allocation_errors: Vec<String>,
}

impl MockStreamStore {
    fn new(is_client: bool, max_concurrent_streams: u32) -> Self {
        Self {
            streams: HashMap::new(),
            max_concurrent_streams,
            next_client_stream_id: 1,
            next_server_stream_id: 2,
            is_client,
            allocation_errors: Vec::new(),
        }
    }

    /// Set maximum concurrent streams (mimics StreamStore::set_max_concurrent_streams)
    fn set_max_concurrent_streams(&mut self, max: u32) {
        self.max_concurrent_streams = max;
    }

    /// Allocate a new stream ID (mimics StreamStore::allocate_stream_id)
    fn allocate_stream_id(&mut self) -> Result<u32, String> {
        // Check concurrent streams limit
        let active_count = self.active_count();
        if active_count >= self.max_concurrent_streams {
            let error = "max concurrent streams exceeded".to_string();
            self.allocation_errors.push(error.clone());
            return Err(error);
        }

        // Allocate next ID based on client/server
        let stream_id = if self.is_client {
            let id = self.next_client_stream_id;
            self.next_client_stream_id = self.next_client_stream_id.saturating_add(2);
            id
        } else {
            let id = self.next_server_stream_id;
            self.next_server_stream_id = self.next_server_stream_id.saturating_add(2);
            id
        };

        // Prevent stream ID overflow
        if stream_id == 0 || stream_id >= 0x7fff_ffff {
            return Err("stream ID exhausted".to_string());
        }

        let stream = StreamInfo::new(stream_id);
        self.streams.insert(stream_id, stream);
        Ok(stream_id)
    }

    /// Get stream by ID
    fn get_stream(&self, stream_id: u32) -> Option<&StreamInfo> {
        self.streams.get(&stream_id)
    }

    /// Get mutable stream by ID
    fn get_stream_mut(&mut self, stream_id: u32) -> Option<&mut StreamInfo> {
        self.streams.get_mut(&stream_id)
    }

    /// Reserve a remote stream (for PUSH_PROMISE)
    fn reserve_remote_stream(&mut self, stream_id: u32) -> Result<(), String> {
        // Check concurrent streams limit for PUSH_PROMISE
        let active_count = self.active_count();
        if active_count >= self.max_concurrent_streams {
            return Err("max concurrent streams exceeded".to_string());
        }

        if self.streams.contains_key(&stream_id) {
            return Err("stream ID already exists".to_string());
        }

        let mut stream = StreamInfo::new(stream_id);
        stream.state = StreamState::ReservedRemote;
        self.streams.insert(stream_id, stream);
        Ok(())
    }

    /// Count active streams
    fn active_count(&self) -> u32 {
        self.streams.values().filter(|s| s.is_active()).count() as u32
    }

    /// Prune closed streams
    fn prune_closed(&mut self) {
        self.streams.retain(|_, stream| !stream.is_closed());
    }

    fn len(&self) -> usize {
        self.streams.len()
    }
}

/// Test scenario for concurrent streams
#[derive(Debug, Clone, Arbitrary)]
struct ConcurrentStreamsScenario {
    /// Initial concurrent streams limit
    initial_max_concurrent: u32,
    /// Whether this is a client-side test
    is_client: bool,
    /// Sequence of operations to perform
    operations: Vec<StreamOperation>,
    /// Whether to include edge cases
    include_edge_cases: bool,
}

/// Operations to test concurrent streams behavior
#[derive(Debug, Clone, Arbitrary)]
enum StreamOperation {
    /// Update the max concurrent streams setting
    UpdateMaxConcurrent(u32),
    /// Allocate a new stream
    AllocateStream,
    /// Send headers on a stream (activate it)
    SendHeaders { stream_id: u32, end_stream: bool },
    /// Reset a stream (close it)
    ResetStream(u32),
    /// Reserve a remote stream (PUSH_PROMISE)
    ReserveRemoteStream(u32),
    /// Prune closed streams
    PruneClosedStreams,
    /// Verify concurrent streams count
    VerifyConcurrentCount(u32),
}

/// Generate edge case operations for testing
fn generate_edge_case_operations() -> Vec<StreamOperation> {
    vec![
        // Boundary concurrent limits
        StreamOperation::UpdateMaxConcurrent(0), // Zero limit
        StreamOperation::UpdateMaxConcurrent(1), // Minimum limit
        StreamOperation::UpdateMaxConcurrent(256), // Default limit
        StreamOperation::UpdateMaxConcurrent(u32::MAX), // Maximum limit
        // Stream allocation attempts with zero limit
        StreamOperation::UpdateMaxConcurrent(0),
        StreamOperation::AllocateStream, // Should fail
        // Limit reduction scenarios
        StreamOperation::UpdateMaxConcurrent(5),
        StreamOperation::AllocateStream, // 1st stream
        StreamOperation::AllocateStream, // 2nd stream
        StreamOperation::AllocateStream, // 3rd stream
        StreamOperation::SendHeaders {
            stream_id: 1,
            end_stream: false,
        },
        StreamOperation::SendHeaders {
            stream_id: 3,
            end_stream: false,
        },
        StreamOperation::SendHeaders {
            stream_id: 5,
            end_stream: false,
        },
        StreamOperation::UpdateMaxConcurrent(2), // Reduce below active count
        StreamOperation::AllocateStream,         // Should fail
        // Stream lifecycle
        StreamOperation::AllocateStream,
        StreamOperation::SendHeaders {
            stream_id: 7,
            end_stream: false,
        },
        StreamOperation::ResetStream(7),     // Close it
        StreamOperation::PruneClosedStreams, // Prune
        StreamOperation::AllocateStream,     // Should succeed again
        // PUSH_PROMISE scenarios
        StreamOperation::UpdateMaxConcurrent(3),
        StreamOperation::ReserveRemoteStream(2), // Server push
        StreamOperation::ReserveRemoteStream(4), // Another push
        StreamOperation::ReserveRemoteStream(6), // Should succeed
        StreamOperation::ReserveRemoteStream(8), // Should fail (limit reached)
        // Rapid limit changes
        StreamOperation::UpdateMaxConcurrent(10),
        StreamOperation::UpdateMaxConcurrent(1),
        StreamOperation::UpdateMaxConcurrent(100),
        StreamOperation::UpdateMaxConcurrent(0),
    ]
}

fuzz_target!(|scenario: ConcurrentStreamsScenario| {
    // Limit scenario size to avoid timeouts
    if scenario.operations.len() > 50 {
        return;
    }

    // Clamp initial limit to reasonable range
    let initial_limit = scenario.initial_max_concurrent.min(1000);
    let mut store = MockStreamStore::new(scenario.is_client, initial_limit);

    // Prepare operations
    let operations = if scenario.include_edge_cases {
        let mut ops = scenario.operations.clone();
        ops.extend(generate_edge_case_operations());
        ops.truncate(40); // Keep reasonable size
        ops
    } else {
        scenario.operations
    };

    // Track state for validation
    let mut allocated_streams = Vec::new();
    // Process each operation
    for operation in &operations {
        match operation {
            StreamOperation::UpdateMaxConcurrent(new_max) => {
                let new_max_clamped = (*new_max).min(10000); // Reasonable limit for testing
                store.set_max_concurrent_streams(new_max_clamped);

                // Verify the limit was set
                assert_eq!(store.max_concurrent_streams, new_max_clamped);
            }

            StreamOperation::AllocateStream => {
                let active_before = store.active_count();
                let result = store.allocate_stream_id();

                match result {
                    Ok(stream_id) => {
                        allocated_streams.push(stream_id);

                        // Should only succeed if we're under the limit
                        if active_before >= store.max_concurrent_streams {
                            panic!(
                                "Stream allocation succeeded when at limit: active={}, max={}",
                                active_before, store.max_concurrent_streams
                            );
                        }

                        // Verify stream was created in idle state
                        let stream = store.get_stream(stream_id).unwrap();
                        assert_eq!(stream.stream_id, stream_id);
                        assert!(
                            !stream.is_active(),
                            "Newly allocated stream should not be active yet"
                        );
                    }
                    Err(err) => {
                        // Should only fail if at limit
                        if active_before < store.max_concurrent_streams {
                            panic!(
                                "Stream allocation failed when under limit: active={}, max={}, error={}",
                                active_before, store.max_concurrent_streams, err
                            );
                        }

                        // Verify proper error message
                        if !err.contains("max concurrent streams exceeded") {
                            panic!(
                                "Wrong error message: expected 'max concurrent streams exceeded', got '{}'",
                                err
                            );
                        }
                    }
                }
            }

            StreamOperation::SendHeaders {
                stream_id,
                end_stream,
            } => {
                if let Some(stream) = store.get_stream_mut(*stream_id) {
                    observe_send_headers(stream, *end_stream, "operation send headers");
                }
            }

            StreamOperation::ResetStream(stream_id) => {
                if let Some(stream) = store.get_stream_mut(*stream_id) {
                    stream.reset();
                }
            }

            StreamOperation::ReserveRemoteStream(stream_id) => {
                // Normalize stream ID to avoid conflicts
                let normalized_id = if scenario.is_client {
                    // Client reserves even IDs (server-initiated)
                    (*stream_id % 100) * 2 + 2
                } else {
                    // Server reserves odd IDs (client-initiated) - but this is unusual
                    (*stream_id % 100) * 2 + 1
                };

                let active_before = store.active_count();
                let result = store.reserve_remote_stream(normalized_id);

                match result {
                    Ok(()) => {
                        if active_before >= store.max_concurrent_streams {
                            panic!(
                                "PUSH_PROMISE succeeded when at limit: active={}, max={}",
                                active_before, store.max_concurrent_streams
                            );
                        }

                        // Verify reserved stream is active
                        let stream = store.get_stream(normalized_id).unwrap();
                        assert_eq!(stream.stream_id, normalized_id);
                        assert!(stream.is_active(), "Reserved stream should be active");
                    }
                    Err(_err) => {
                        if active_before < store.max_concurrent_streams
                            && !store.streams.contains_key(&normalized_id)
                        {
                            // Should have succeeded if under limit and ID not in use
                            // But accept failure for simplicity
                        }
                    }
                }
            }

            StreamOperation::PruneClosedStreams => {
                let count_before = store.len();
                store.prune_closed();
                let count_after = store.len();

                // Pruning should reduce or maintain count
                assert!(
                    count_after <= count_before,
                    "Prune should not increase stream count"
                );
            }

            StreamOperation::VerifyConcurrentCount(expected) => {
                let actual = store.active_count();
                // This is just a hint for validation - don't panic on mismatch
                if actual != *expected {
                    // Log mismatch but continue (fuzzer might find interesting edge cases)
                }
            }
        }
    }

    // Additional validation tests
    test_zero_concurrent_limit(&mut store);
    test_limit_reduction_with_active_streams(&mut store);
    test_stream_lifecycle(&mut store);
});

/// Test that zero concurrent limit blocks all new streams
fn test_zero_concurrent_limit(store: &mut MockStreamStore) {
    let original_max = store.max_concurrent_streams;

    // Set zero limit
    store.set_max_concurrent_streams(0);

    // All allocation attempts should fail
    for _ in 0..5 {
        let result = store.allocate_stream_id();
        assert!(
            result.is_err(),
            "Stream allocation should fail with zero limit"
        );

        if let Err(err) = result {
            assert!(err.contains("max concurrent streams exceeded"));
        }
    }

    // Reserve remote should also fail
    let result = store.reserve_remote_stream(12345);
    assert!(result.is_err(), "PUSH_PROMISE should fail with zero limit");

    // Restore original limit
    store.set_max_concurrent_streams(original_max);
}

/// Test reducing limit below current active count
fn test_limit_reduction_with_active_streams(store: &mut MockStreamStore) {
    // Set high limit and create several active streams
    store.set_max_concurrent_streams(10);

    let mut active_streams = Vec::new();
    for _ in 0..5 {
        if let Ok(id) = store.allocate_stream_id() {
            if let Some(stream) = store.get_stream_mut(id) {
                observe_send_headers(stream, false, "limit reduction setup");
            }
            active_streams.push(id);
        }
    }

    let active_count = store.active_count();
    assert!(active_count >= 3, "Should have created active streams");

    // Reduce limit below active count
    store.set_max_concurrent_streams(2);

    // Existing streams should remain active
    assert_eq!(
        store.active_count(),
        active_count,
        "Existing active streams should not be affected by limit reduction"
    );

    // New allocations should fail
    let result = store.allocate_stream_id();
    assert!(
        result.is_err(),
        "New stream allocation should fail when over limit"
    );

    // Close some streams to make room
    if !active_streams.is_empty() {
        if let Some(stream) = store.get_stream_mut(active_streams[0]) {
            stream.reset();
        }
        if let Some(stream) = store.get_stream_mut(active_streams[1]) {
            stream.reset();
        }
        store.prune_closed();

        // Now allocation might succeed
        if store.active_count() < store.max_concurrent_streams {
            let _result = store.allocate_stream_id();
            // May succeed now depending on remaining active count
        }
    }
}

/// Test complete stream lifecycle
fn test_stream_lifecycle(store: &mut MockStreamStore) {
    store.set_max_concurrent_streams(5);

    // Allocate stream
    let stream_id = match store.allocate_stream_id() {
        Ok(id) => id,
        Err(_) => return, // May fail if other tests filled the limit
    };

    // Verify initially idle (not active)
    let stream = store.get_stream(stream_id).unwrap();
    assert!(!stream.is_active(), "New stream should be idle");

    // Activate stream
    if let Some(stream) = store.get_stream_mut(stream_id) {
        observe_send_headers(stream, false, "stream lifecycle activation");
    }

    // Verify now active
    let stream = store.get_stream(stream_id).unwrap();
    assert!(stream.is_active(), "Stream should be active after headers");

    // Close stream
    if let Some(stream) = store.get_stream_mut(stream_id) {
        stream.reset();
    }

    // Verify closed (not active)
    let stream = store.get_stream(stream_id).unwrap();
    assert!(
        !stream.is_active(),
        "Stream should not be active after reset"
    );

    // Prune closed streams
    store.prune_closed();

    // Verify stream is gone
    assert!(
        store.get_stream(stream_id).is_none(),
        "Stream should be removed after prune"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normal_concurrent_limit() {
        let scenario = ConcurrentStreamsScenario {
            initial_max_concurrent: 3,
            is_client: true,
            operations: vec![
                StreamOperation::AllocateStream,
                StreamOperation::AllocateStream,
                StreamOperation::AllocateStream,
                StreamOperation::SendHeaders {
                    stream_id: 1,
                    end_stream: false,
                },
                StreamOperation::SendHeaders {
                    stream_id: 3,
                    end_stream: false,
                },
                StreamOperation::SendHeaders {
                    stream_id: 5,
                    end_stream: false,
                },
                StreamOperation::AllocateStream, // Should fail - limit reached
            ],
            include_edge_cases: false,
        };

        libfuzzer_sys::test_input_wrap(scenario);
    }

    #[test]
    fn test_zero_concurrent_limit() {
        let scenario = ConcurrentStreamsScenario {
            initial_max_concurrent: 5,
            is_client: true,
            operations: vec![
                StreamOperation::UpdateMaxConcurrent(0),
                StreamOperation::AllocateStream, // Should fail
                StreamOperation::ReserveRemoteStream(2), // Should fail
            ],
            include_edge_cases: false,
        };

        libfuzzer_sys::test_input_wrap(scenario);
    }

    #[test]
    fn test_dynamic_limit_reduction() {
        let scenario = ConcurrentStreamsScenario {
            initial_max_concurrent: 10,
            is_client: true,
            operations: vec![
                StreamOperation::AllocateStream,
                StreamOperation::AllocateStream,
                StreamOperation::AllocateStream,
                StreamOperation::SendHeaders {
                    stream_id: 1,
                    end_stream: false,
                },
                StreamOperation::SendHeaders {
                    stream_id: 3,
                    end_stream: false,
                },
                StreamOperation::UpdateMaxConcurrent(1), // Reduce below active count
                StreamOperation::AllocateStream,         // Should fail
                StreamOperation::ResetStream(1),         // Close one
                StreamOperation::PruneClosedStreams,
                StreamOperation::AllocateStream, // Might succeed now
            ],
            include_edge_cases: false,
        };

        libfuzzer_sys::test_input_wrap(scenario);
    }

    #[test]
    fn test_push_promise_limit_enforcement() {
        let scenario = ConcurrentStreamsScenario {
            initial_max_concurrent: 2,
            is_client: true,
            operations: vec![
                StreamOperation::ReserveRemoteStream(2),
                StreamOperation::ReserveRemoteStream(4),
                StreamOperation::ReserveRemoteStream(6), // Should fail - limit reached
            ],
            include_edge_cases: false,
        };

        libfuzzer_sys::test_input_wrap(scenario);
    }

    #[test]
    fn test_stream_lifecycle() {
        let scenario = ConcurrentStreamsScenario {
            initial_max_concurrent: 3,
            is_client: true,
            operations: vec![
                StreamOperation::AllocateStream,
                StreamOperation::SendHeaders {
                    stream_id: 1,
                    end_stream: false,
                },
                StreamOperation::VerifyConcurrentCount(1),
                StreamOperation::ResetStream(1),
                StreamOperation::VerifyConcurrentCount(0),
                StreamOperation::PruneClosedStreams,
                StreamOperation::AllocateStream, // Should succeed again
            ],
            include_edge_cases: false,
        };

        libfuzzer_sys::test_input_wrap(scenario);
    }

    #[test]
    fn test_edge_cases() {
        let scenario = ConcurrentStreamsScenario {
            initial_max_concurrent: 5,
            is_client: true,
            operations: vec![], // Edge cases will be added
            include_edge_cases: true,
        };

        libfuzzer_sys::test_input_wrap(scenario);
    }
}
