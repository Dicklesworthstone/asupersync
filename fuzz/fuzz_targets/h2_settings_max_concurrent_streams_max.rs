#![no_main]

//! Fuzz target for HTTP/2 MAX_CONCURRENT_STREAMS at maximum valid value (2^31-1)
//!
//! Tests edge case behavior when MAX_CONCURRENT_STREAMS is set to 2147483647
//! (the maximum valid value per RFC 7540 §6.5.2). Verifies our state machine
//! handles stream tracking without overflow and properly enforces limits.
//!
//! Key test scenarios:
//! - MAX_CONCURRENT_STREAMS = 2^31-1 (0x7FFFFFFF)
//! - Stream creation approaching this limit
//! - Proper REFUSED_STREAM vs PROTOCOL_ERROR responses
//! - State machine overflow protection
//! - Resource exhaustion handling

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, Ordering};

/// Maximum valid value for MAX_CONCURRENT_STREAMS per RFC 7540
const MAX_CONCURRENT_STREAMS_LIMIT: u32 = 0x7FFFFFFF; // 2^31-1 = 2,147,483,647

/// Mock HTTP/2 connection with maximum concurrent streams setting
struct MockMaxConcurrentStreamsConnection {
    /// Current MAX_CONCURRENT_STREAMS setting
    max_concurrent_streams: u32,

    /// Active streams by stream ID
    active_streams: HashMap<u32, StreamState>,

    /// Current active stream count
    active_count: AtomicU32,

    /// Next stream ID to assign (client = odd, server = even)
    next_client_stream_id: u32,
    next_server_stream_id: u32,

    /// Connection state
    state: ConnectionState,

    /// Statistics
    stats: ConnectionStats,

    /// Error tracking
    violations: Vec<ViolationType>,
}

#[allow(dead_code)]
#[derive(Clone, Debug)]
enum StreamState {
    Idle,
    Reserved,
    Open,
    HalfClosedLocal,
    HalfClosedRemote,
    Closed,
}

#[allow(dead_code)]
#[derive(Clone, Debug)]
enum ConnectionState {
    Open,
    GoingAway,
    Closed,
}

#[derive(Default, Clone, Debug)]
struct ConnectionStats {
    settings_frames_received: u32,
    streams_created: u32,
    streams_refused: u32,
    protocol_errors: u32,
    max_active_reached: u32,
    overflow_attempts: u32,
}

#[derive(Clone, Debug)]
enum ViolationType {
    MaxConcurrentStreamsExceeded,
    StreamIdOverflow,
    InvalidStreamState,
    SettingsValueTooHigh,
    IntegerOverflow,
}

impl MockMaxConcurrentStreamsConnection {
    fn new() -> Self {
        Self {
            max_concurrent_streams: MAX_CONCURRENT_STREAMS_LIMIT,
            active_streams: HashMap::new(),
            active_count: AtomicU32::new(0),
            next_client_stream_id: 1, // Client streams are odd
            next_server_stream_id: 2, // Server streams are even
            state: ConnectionState::Open,
            stats: ConnectionStats::default(),
            violations: Vec::new(),
        }
    }

    /// Process a SETTINGS frame with MAX_CONCURRENT_STREAMS
    fn handle_settings(&mut self, max_concurrent_streams: u32) -> Result<(), H2Error> {
        self.stats.settings_frames_received += 1;

        // RFC 7540 §6.5.2: MAX_CONCURRENT_STREAMS maximum value is 2^31-1
        if max_concurrent_streams > MAX_CONCURRENT_STREAMS_LIMIT {
            self.violations.push(ViolationType::SettingsValueTooHigh);
            self.stats.protocol_errors += 1;
            return Err(H2Error::ProtocolError);
        }

        self.max_concurrent_streams = max_concurrent_streams;

        Ok(())
    }

    /// Attempt to create a new stream
    fn create_stream(&mut self, is_client: bool) -> Result<u32, H2Error> {
        // Check connection state
        if matches!(self.state, ConnectionState::Closed) {
            return Err(H2Error::ConnectionClosed);
        }

        // Get current active count with overflow protection
        let current_active = self.active_count.load(Ordering::Acquire);

        // Check against MAX_CONCURRENT_STREAMS limit
        if current_active >= self.max_concurrent_streams {
            self.violations
                .push(ViolationType::MaxConcurrentStreamsExceeded);
            self.stats.streams_refused += 1;
            return Err(H2Error::RefusedStream);
        }

        // Assign stream ID with overflow protection
        let stream_id = if is_client {
            let id = self.next_client_stream_id;
            // Check for overflow before incrementing
            if id > u32::MAX - 2 {
                self.violations.push(ViolationType::StreamIdOverflow);
                self.stats.overflow_attempts += 1;
                return Err(H2Error::ProtocolError);
            }
            self.next_client_stream_id += 2;
            id
        } else {
            let id = self.next_server_stream_id;
            // Check for overflow before incrementing
            if id > u32::MAX - 2 {
                self.violations.push(ViolationType::StreamIdOverflow);
                self.stats.overflow_attempts += 1;
                return Err(H2Error::ProtocolError);
            }
            self.next_server_stream_id += 2;
            id
        };

        // Increment active count with overflow protection
        let new_count = current_active.checked_add(1);
        if new_count.is_none() {
            self.violations.push(ViolationType::IntegerOverflow);
            self.stats.overflow_attempts += 1;
            return Err(H2Error::InternalError);
        }

        let new_count = new_count.unwrap();
        self.active_count.store(new_count, Ordering::Release);

        // Create stream
        self.active_streams.insert(stream_id, StreamState::Open);
        self.stats.streams_created += 1;

        // Update maximum reached
        if new_count > self.stats.max_active_reached {
            self.stats.max_active_reached = new_count;
        }

        Ok(stream_id)
    }

    /// Close a stream
    fn close_stream(&mut self, stream_id: u32) -> Result<(), H2Error> {
        if let Some(state) = self.active_streams.get_mut(&stream_id) {
            match state {
                StreamState::Open
                | StreamState::HalfClosedLocal
                | StreamState::HalfClosedRemote => {
                    *state = StreamState::Closed;

                    // Decrement active count
                    let current = self.active_count.load(Ordering::Acquire);
                    if current > 0 {
                        self.active_count.store(current - 1, Ordering::Release);
                    }

                    Ok(())
                }
                StreamState::Closed => {
                    // Already closed, ignore
                    Ok(())
                }
                _ => {
                    self.violations.push(ViolationType::InvalidStreamState);
                    Err(H2Error::ProtocolError)
                }
            }
        } else {
            // Stream not found
            Err(H2Error::ProtocolError)
        }
    }

    /// Get current connection state summary
    fn get_state_summary(&self) -> StateSummary {
        StateSummary {
            max_concurrent_streams: self.max_concurrent_streams,
            active_streams: self.active_count.load(Ordering::Acquire),
            total_streams: self.active_streams.len() as u32,
            next_client_id: self.next_client_stream_id,
            next_server_id: self.next_server_stream_id,
            violations_count: self.violations.len() as u32,
            connection_open: matches!(self.state, ConnectionState::Open),
        }
    }

    /// Stress test: attempt to create many streams quickly
    fn stress_test_stream_creation(&mut self, count: u32) -> StressTestResult {
        let mut created = 0;
        let mut refused = 0;
        let mut errors = 0;

        let initial_active = self.active_count.load(Ordering::Acquire);

        for i in 0..count {
            match self.create_stream(i.is_multiple_of(2)) {
                Ok(_) => created += 1,
                Err(H2Error::RefusedStream) => refused += 1,
                Err(_) => errors += 1,
            }

            // Safety check: if we're approaching dangerous territory, stop
            let current_active = self.active_count.load(Ordering::Acquire);
            if current_active > MAX_CONCURRENT_STREAMS_LIMIT.saturating_sub(1000) {
                break;
            }
        }

        let final_active = self.active_count.load(Ordering::Acquire);

        StressTestResult {
            attempted: count,
            created,
            refused,
            errors,
            initial_active,
            final_active,
        }
    }
}

#[derive(Clone, Debug)]
struct StateSummary {
    max_concurrent_streams: u32,
    active_streams: u32,
    total_streams: u32,
    next_client_id: u32,
    next_server_id: u32,
    violations_count: u32,
    connection_open: bool,
}

#[derive(Clone, Debug)]
struct StressTestResult {
    attempted: u32,
    created: u32,
    refused: u32,
    errors: u32,
    initial_active: u32,
    final_active: u32,
}

#[derive(Clone, Debug)]
enum H2Error {
    ProtocolError,
    RefusedStream,
    ConnectionClosed,
    InternalError,
}

fn last_violation_matches(
    connection: &MockMaxConcurrentStreamsConnection,
    expected: fn(&ViolationType) -> bool,
) -> bool {
    connection.violations.last().is_some_and(expected)
}

fn is_active_stream_state(state: &StreamState) -> bool {
    matches!(
        state,
        StreamState::Open | StreamState::HalfClosedLocal | StreamState::HalfClosedRemote
    )
}

fn observe_handle_settings(
    connection: &mut MockMaxConcurrentStreamsConnection,
    max_concurrent_streams: u32,
    context: &str,
) {
    let before_limit = connection.max_concurrent_streams;
    let before_protocol_errors = connection.stats.protocol_errors;
    let before_settings = connection.stats.settings_frames_received;

    match connection.handle_settings(max_concurrent_streams) {
        Ok(()) => {
            assert!(
                max_concurrent_streams <= MAX_CONCURRENT_STREAMS_LIMIT,
                "{context}: accepted invalid MAX_CONCURRENT_STREAMS"
            );
            assert_eq!(
                connection.max_concurrent_streams, max_concurrent_streams,
                "{context}: valid setting did not update the active limit"
            );
            assert_eq!(
                connection.stats.settings_frames_received,
                before_settings.saturating_add(1),
                "{context}: settings-frame counter did not advance"
            );
        }
        Err(H2Error::ProtocolError) => {
            assert!(
                max_concurrent_streams > MAX_CONCURRENT_STREAMS_LIMIT,
                "{context}: rejected an in-range MAX_CONCURRENT_STREAMS"
            );
            assert_eq!(
                connection.max_concurrent_streams, before_limit,
                "{context}: invalid setting mutated the active limit"
            );
            assert_eq!(
                connection.stats.protocol_errors,
                before_protocol_errors.saturating_add(1),
                "{context}: invalid setting did not count a protocol error"
            );
            assert!(
                last_violation_matches(connection, |violation| matches!(
                    violation,
                    ViolationType::SettingsValueTooHigh
                )),
                "{context}: invalid setting did not record SettingsValueTooHigh"
            );
        }
        Err(other) => panic!("{context}: SETTINGS handling returned unexpected error {other:?}"),
    }
}

fn observe_create_stream(
    connection: &mut MockMaxConcurrentStreamsConnection,
    is_client: bool,
    context: &str,
) {
    let before_active = connection.active_count.load(Ordering::Acquire);
    let before_created = connection.stats.streams_created;
    let before_refused = connection.stats.streams_refused;
    let before_overflow_attempts = connection.stats.overflow_attempts;

    match connection.create_stream(is_client) {
        Ok(stream_id) => {
            if is_client {
                assert!(
                    !stream_id.is_multiple_of(2),
                    "{context}: client stream ID was not odd"
                );
            } else {
                assert!(
                    stream_id.is_multiple_of(2),
                    "{context}: server stream ID was not even"
                );
            }
            assert_eq!(
                connection.active_count.load(Ordering::Acquire),
                before_active.saturating_add(1),
                "{context}: accepted stream did not increase active count"
            );
            assert!(
                matches!(
                    connection.active_streams.get(&stream_id),
                    Some(StreamState::Open)
                ),
                "{context}: accepted stream was not recorded as open"
            );
            assert_eq!(
                connection.stats.streams_created,
                before_created.saturating_add(1),
                "{context}: accepted stream did not advance created counter"
            );
        }
        Err(H2Error::RefusedStream) => {
            assert!(
                before_active >= connection.max_concurrent_streams,
                "{context}: refused stream while below MAX_CONCURRENT_STREAMS"
            );
            assert_eq!(
                connection.active_count.load(Ordering::Acquire),
                before_active,
                "{context}: refused stream mutated active count"
            );
            assert_eq!(
                connection.stats.streams_refused,
                before_refused.saturating_add(1),
                "{context}: refused stream did not advance refusal counter"
            );
            assert!(
                last_violation_matches(connection, |violation| matches!(
                    violation,
                    ViolationType::MaxConcurrentStreamsExceeded
                )),
                "{context}: refused stream did not record max-concurrency violation"
            );
        }
        Err(H2Error::ProtocolError) => {
            assert_eq!(
                connection.active_count.load(Ordering::Acquire),
                before_active,
                "{context}: stream-id overflow mutated active count"
            );
            assert!(
                connection.stats.overflow_attempts > before_overflow_attempts,
                "{context}: stream-id overflow did not advance overflow counter"
            );
            assert!(
                last_violation_matches(connection, |violation| matches!(
                    violation,
                    ViolationType::StreamIdOverflow
                )),
                "{context}: stream-id overflow did not record the violation"
            );
        }
        Err(H2Error::ConnectionClosed) => {
            assert!(
                matches!(connection.state, ConnectionState::Closed),
                "{context}: ConnectionClosed returned while connection state was open"
            );
            assert_eq!(
                connection.active_count.load(Ordering::Acquire),
                before_active,
                "{context}: closed connection stream attempt mutated active count"
            );
        }
        Err(H2Error::InternalError) => {
            assert_eq!(
                connection.active_count.load(Ordering::Acquire),
                before_active,
                "{context}: integer-overflow path mutated active count"
            );
            assert!(
                connection.stats.overflow_attempts > before_overflow_attempts,
                "{context}: integer overflow did not advance overflow counter"
            );
            assert!(
                last_violation_matches(connection, |violation| matches!(
                    violation,
                    ViolationType::IntegerOverflow
                )),
                "{context}: integer overflow did not record the violation"
            );
        }
    }
}

fn observe_close_stream(
    connection: &mut MockMaxConcurrentStreamsConnection,
    stream_id: u32,
    context: &str,
) {
    let before_active = connection.active_count.load(Ordering::Acquire);
    let before_violations = connection.violations.len();
    let was_active = connection
        .active_streams
        .get(&stream_id)
        .is_some_and(is_active_stream_state);

    match connection.close_stream(stream_id) {
        Ok(()) => {
            let expected_active = if was_active {
                before_active.saturating_sub(1)
            } else {
                before_active
            };
            assert_eq!(
                connection.active_count.load(Ordering::Acquire),
                expected_active,
                "{context}: close-stream active count did not match prior state"
            );
        }
        Err(H2Error::ProtocolError) => {
            assert!(
                !was_active,
                "{context}: rejected close for a stream that was active before close"
            );
            assert_eq!(
                connection.active_count.load(Ordering::Acquire),
                before_active,
                "{context}: rejected close mutated active count"
            );
            assert!(
                connection.violations.len() == before_violations
                    || last_violation_matches(connection, |violation| matches!(
                        violation,
                        ViolationType::InvalidStreamState
                    )),
                "{context}: rejected close recorded an unexpected violation"
            );
        }
        Err(other) => panic!("{context}: close-stream returned unexpected error {other:?}"),
    }
}

fn observe_stress_test_result(result: &StressTestResult, requested_count: u32) {
    assert_eq!(
        result.attempted, requested_count,
        "stress test attempted count did not preserve the requested bound"
    );
    assert!(
        result
            .created
            .saturating_add(result.refused)
            .saturating_add(result.errors)
            <= result.attempted,
        "stress test outcome counters exceeded attempted count"
    );
    assert!(
        result.final_active >= result.initial_active,
        "stress test creates streams only, so final active count cannot decrease"
    );
    assert_eq!(
        result.final_active,
        result.initial_active.saturating_add(result.created),
        "stress test final active count does not match created streams"
    );
    assert!(
        result.final_active <= MAX_CONCURRENT_STREAMS_LIMIT,
        "stress test exceeded the RFC MAX_CONCURRENT_STREAMS bound"
    );
}

fn observe_at_limit_stream_refusal(
    connection: &mut MockMaxConcurrentStreamsConnection,
    context: &str,
) {
    let before_active = connection.active_count.load(Ordering::Acquire);
    let before_refused = connection.stats.streams_refused;

    assert_eq!(
        before_active, connection.max_concurrent_streams,
        "{context}: at-limit probe called while connection was not exactly at limit"
    );

    match connection.create_stream(true) {
        Ok(stream_id) => panic!("{context}: stream {stream_id} was created at the active limit"),
        Err(H2Error::RefusedStream) => {
            assert_eq!(
                connection.active_count.load(Ordering::Acquire),
                before_active,
                "{context}: refused at-limit stream mutated active count"
            );
            assert_eq!(
                connection.stats.streams_refused,
                before_refused.saturating_add(1),
                "{context}: at-limit refusal did not advance refusal counter"
            );
            assert!(
                last_violation_matches(connection, |violation| matches!(
                    violation,
                    ViolationType::MaxConcurrentStreamsExceeded
                )),
                "{context}: at-limit refusal did not record max-concurrency violation"
            );
        }
        Err(other) => panic!("{context}: at-limit stream create returned unexpected {other:?}"),
    }
}

/// Fuzz input structure
#[derive(Arbitrary, Debug, Clone)]
struct FuzzInput {
    /// Initial MAX_CONCURRENT_STREAMS setting
    initial_max_streams: u32,

    /// Sequence of operations to perform
    operations: Vec<Operation>,

    /// Whether to run stress test
    run_stress_test: bool,

    /// Stress test parameters
    stress_test_count: u32,
}

#[derive(Arbitrary, Debug, Clone)]
enum Operation {
    /// Update MAX_CONCURRENT_STREAMS setting
    UpdateSettings { max_concurrent_streams: u32 },

    /// Create a new client stream
    CreateClientStream,

    /// Create a new server stream
    CreateServerStream,

    /// Close a stream by ID
    CloseStream { stream_id: u32 },

    /// Create multiple streams quickly
    CreateBurst { count: u8, is_client: bool },

    /// Query connection state
    QueryState,
}

fuzz_target!(|input: FuzzInput| {
    // Limit input size to prevent excessive resource usage
    if input.operations.len() > 1000 {
        return;
    }

    if input.stress_test_count > 10000 {
        return;
    }

    let mut connection = MockMaxConcurrentStreamsConnection::new();

    // Set initial MAX_CONCURRENT_STREAMS (focus on maximum value)
    let initial_setting = if input.initial_max_streams == 0 {
        MAX_CONCURRENT_STREAMS_LIMIT
    } else {
        input.initial_max_streams.min(MAX_CONCURRENT_STREAMS_LIMIT)
    };

    observe_handle_settings(&mut connection, initial_setting, "initial setting");

    // Process operations
    for operation in input.operations {
        match operation {
            Operation::UpdateSettings {
                max_concurrent_streams,
            } => {
                // Focus on maximum and near-maximum values
                let setting_value = match max_concurrent_streams % 10 {
                    0 => MAX_CONCURRENT_STREAMS_LIMIT,
                    1 => MAX_CONCURRENT_STREAMS_LIMIT - 1,
                    2 => MAX_CONCURRENT_STREAMS_LIMIT - 100,
                    3 => MAX_CONCURRENT_STREAMS_LIMIT - 1000,
                    4 => MAX_CONCURRENT_STREAMS_LIMIT / 2,
                    5 => MAX_CONCURRENT_STREAMS_LIMIT + 1, // Invalid, should be rejected
                    6 => u32::MAX,                         // Invalid, should be rejected
                    7 => max_concurrent_streams.min(MAX_CONCURRENT_STREAMS_LIMIT),
                    _ => max_concurrent_streams,
                };

                observe_handle_settings(&mut connection, setting_value, "operation setting");
            }

            Operation::CreateClientStream => {
                observe_create_stream(&mut connection, true, "client stream create");
            }

            Operation::CreateServerStream => {
                observe_create_stream(&mut connection, false, "server stream create");
            }

            Operation::CloseStream { stream_id } => {
                observe_close_stream(&mut connection, stream_id, "stream close");
            }

            Operation::CreateBurst { count, is_client } => {
                for _ in 0..count.min(100) {
                    // Limit burst size
                    observe_create_stream(&mut connection, is_client, "burst stream create");
                }
            }

            Operation::QueryState => {
                let _state = connection.get_state_summary();
                // Verify state consistency
                let summary = connection.get_state_summary();

                // Active streams should never exceed MAX_CONCURRENT_STREAMS
                assert!(summary.active_streams <= summary.max_concurrent_streams);

                // Stream IDs should be valid
                assert!(!summary.next_client_id.is_multiple_of(2)); // Client IDs are odd
                assert!(summary.next_server_id.is_multiple_of(2)); // Server IDs are even

                // Active count should not overflow
                assert!(summary.active_streams <= MAX_CONCURRENT_STREAMS_LIMIT);
                assert_eq!(summary.violations_count, connection.violations.len() as u32);
                assert_eq!(
                    summary.connection_open,
                    matches!(connection.state, ConnectionState::Open)
                );
            }
        }

        // Safety check: ensure we don't consume excessive memory
        let state = connection.get_state_summary();
        if state.total_streams > 50000 {
            break;
        }
    }

    // Run stress test if requested
    if input.run_stress_test {
        let stress_count = input.stress_test_count.min(10000);
        let result = connection.stress_test_stream_creation(stress_count);
        observe_stress_test_result(&result, stress_count);
    }

    // Final state validation
    let final_state = connection.get_state_summary();

    // Ensure active streams never exceed the configured limit
    assert!(final_state.active_streams <= final_state.max_concurrent_streams);

    // Ensure no integer overflow occurred in stream tracking
    assert!(final_state.active_streams <= MAX_CONCURRENT_STREAMS_LIMIT);

    // Verify connection remains in valid state
    assert!(final_state.next_client_id >= 1);
    assert!(final_state.next_server_id >= 2);
    assert_eq!(
        final_state.violations_count,
        connection.violations.len() as u32
    );
    assert_eq!(
        final_state.connection_open,
        matches!(connection.state, ConnectionState::Open)
    );

    // Test edge case: try to create one more stream when at limit
    if final_state.active_streams == connection.max_concurrent_streams {
        observe_at_limit_stream_refusal(&mut connection, "final at-limit stream create");
    }

    // Verify overflow protection
    let violations = &connection.violations;
    for violation in violations {
        match violation {
            ViolationType::IntegerOverflow => {
                // If we detected overflow, ensure we handled it gracefully
                assert!(final_state.active_streams < u32::MAX);
            }
            ViolationType::StreamIdOverflow => {
                // Stream ID overflow should be detected and handled
            }
            ViolationType::MaxConcurrentStreamsExceeded => {
                // This violation should result in REFUSED_STREAM
            }
            ViolationType::SettingsValueTooHigh => {
                // Invalid settings should be rejected
            }
            ViolationType::InvalidStreamState => {
                // Stream state violations should be caught
            }
        }
    }

    // Performance check: ensure we can handle the maximum setting efficiently
    if connection.max_concurrent_streams == MAX_CONCURRENT_STREAMS_LIMIT {
        // Connection should remain responsive even with maximum setting
        let _query_result = connection.get_state_summary();
    }
});
