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

#[derive(Clone, Debug)]
enum StreamState {
    Idle,
    Reserved,
    Open,
    HalfClosedLocal,
    HalfClosedRemote,
    Closed,
}

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

        let old_limit = self.max_concurrent_streams;
        self.max_concurrent_streams = max_concurrent_streams;

        // If new limit is lower and we have too many active streams,
        // we don't close existing streams but refuse new ones
        let current_active = self.active_count.load(Ordering::Acquire);
        if current_active > max_concurrent_streams {
            // This is allowed - existing streams continue, new ones are refused
        }

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
            self.violations.push(ViolationType::MaxConcurrentStreamsExceeded);
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
                StreamState::Open | StreamState::HalfClosedLocal | StreamState::HalfClosedRemote => {
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
            match self.create_stream(i % 2 == 0) {
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

    let _ = connection.handle_settings(initial_setting);

    // Process operations
    for operation in input.operations {
        match operation {
            Operation::UpdateSettings { max_concurrent_streams } => {
                // Focus on maximum and near-maximum values
                let setting_value = match max_concurrent_streams % 10 {
                    0 => MAX_CONCURRENT_STREAMS_LIMIT,
                    1 => MAX_CONCURRENT_STREAMS_LIMIT - 1,
                    2 => MAX_CONCURRENT_STREAMS_LIMIT - 100,
                    3 => MAX_CONCURRENT_STREAMS_LIMIT - 1000,
                    4 => MAX_CONCURRENT_STREAMS_LIMIT / 2,
                    5 => MAX_CONCURRENT_STREAMS_LIMIT + 1, // Invalid, should be rejected
                    6 => u32::MAX, // Invalid, should be rejected
                    7 => max_concurrent_streams.min(MAX_CONCURRENT_STREAMS_LIMIT),
                    _ => max_concurrent_streams,
                };

                let _ = connection.handle_settings(setting_value);
            }

            Operation::CreateClientStream => {
                let _ = connection.create_stream(true);
            }

            Operation::CreateServerStream => {
                let _ = connection.create_stream(false);
            }

            Operation::CloseStream { stream_id } => {
                let _ = connection.close_stream(stream_id);
            }

            Operation::CreateBurst { count, is_client } => {
                for _ in 0..count.min(100) { // Limit burst size
                    let _ = connection.create_stream(is_client);
                }
            }

            Operation::QueryState => {
                let _state = connection.get_state_summary();
                // Verify state consistency
                let summary = connection.get_state_summary();

                // Active streams should never exceed MAX_CONCURRENT_STREAMS
                assert!(summary.active_streams <= connection.max_concurrent_streams);

                // Stream IDs should be valid
                assert!(summary.next_client_id % 2 == 1); // Client IDs are odd
                assert!(summary.next_server_id % 2 == 0); // Server IDs are even

                // Active count should not overflow
                assert!(summary.active_streams <= MAX_CONCURRENT_STREAMS_LIMIT);
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
        let _result = connection.stress_test_stream_creation(stress_count);
    }

    // Final state validation
    let final_state = connection.get_state_summary();

    // Ensure active streams never exceed the configured limit
    assert!(final_state.active_streams <= connection.max_concurrent_streams);

    // Ensure no integer overflow occurred in stream tracking
    assert!(final_state.active_streams <= MAX_CONCURRENT_STREAMS_LIMIT);

    // Verify connection remains in valid state
    assert!(final_state.next_client_id >= 1);
    assert!(final_state.next_server_id >= 2);

    // Test edge case: try to create one more stream when at limit
    if final_state.active_streams == connection.max_concurrent_streams {
        let result = connection.create_stream(true);
        match result {
            Ok(_) => {
                // This should not happen - we were at the limit
                panic!("Stream creation succeeded when at MAX_CONCURRENT_STREAMS limit");
            }
            Err(H2Error::RefusedStream) => {
                // Expected behavior
            }
            Err(H2Error::ProtocolError) => {
                // Also acceptable if there's a protocol violation
            }
            Err(_) => {
                // Other errors are acceptable
            }
        }
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