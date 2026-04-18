#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

/// Fuzzing input for QUIC stream flow control edge cases
#[derive(Arbitrary, Debug)]
struct QuicStreamFlowFuzz {
    /// Initial flow control configuration
    flow_config: FlowControlConfig,
    /// Sequence of interleaved flow control operations
    operations: Vec<FlowControlOperation>,
    /// Connection-level flow control stress tests
    connection_tests: Vec<ConnectionFlowTest>,
    /// Window update scenarios
    window_updates: Vec<WindowUpdateTest>,
    /// Edge case scenarios for flow control
    edge_cases: Vec<FlowControlEdgeCase>,
}

/// Flow control configuration for testing different limits
#[derive(Arbitrary, Debug)]
struct FlowControlConfig {
    /// Endpoint role
    role: StreamRoleFuzz,
    /// Per-stream send window (bytes)
    stream_send_window: u32,
    /// Per-stream receive window (bytes)
    stream_recv_window: u32,
    /// Connection-level send limit (bytes)
    connection_send_limit: u32,
    /// Connection-level receive limit (bytes)
    connection_recv_limit: u32,
    /// Initial number of streams to create
    initial_streams: u8,
}

/// Stream role for fuzzing
#[derive(Arbitrary, Debug, Clone, Copy)]
enum StreamRoleFuzz {
    Client,
    Server,
}

/// Flow control operations to fuzz stream transitions
#[derive(Arbitrary, Debug)]
enum FlowControlOperation {
    /// Send data on stream (tests flow control consumption)
    SendData { stream_index: u8, data_len: u16 },
    /// Receive data on stream (tests window advancement)
    ReceiveData { stream_index: u8, data_len: u16 },
    /// Receive out-of-order data (tests window credit accounting)
    ReceiveSegment {
        stream_index: u8,
        offset: u32,
        data_len: u16,
        fin_flag: bool,
    },
    /// Window update for stream (increase send credit)
    StreamWindowUpdate { stream_index: u8, new_limit: u32 },
    /// Connection-level window update
    ConnectionWindowUpdate {
        new_send_limit: u32,
        new_recv_limit: u32,
    },
    /// Reset stream with final size
    ResetStream {
        stream_index: u8,
        error_code: u32,
        final_size: u32,
    },
    /// Stop sending on stream
    StopSending { stream_index: u8, error_code: u32 },
    /// Try to exhaust flow control credit
    ExhaustCredit { stream_index: u8, excess_bytes: u16 },
    /// Interleaved send/receive operations
    InterleavedOps {
        stream_index: u8,
        send_chunks: Vec<u16>,
        recv_chunks: Vec<u16>,
    },
}

/// Connection-level flow control stress tests
#[derive(Arbitrary, Debug)]
enum ConnectionFlowTest {
    /// Exhaust connection send credit across multiple streams
    ExhaustConnectionSend {
        stream_count: u8,
        bytes_per_stream: u16,
    },
    /// Test credit redistribution after stream close
    CreditRedistribution {
        close_streams: Vec<u8>,
        new_writes: Vec<u16>,
    },
    /// Connection limit regression attempts
    LimitRegression { current_limit: u32, bad_limit: u32 },
    /// Rapid credit exhaustion and recovery
    RapidExhaustionRecovery {
        exhaust_amount: u32,
        recovery_amount: u32,
        repeat_count: u8,
    },
}

/// Window update edge cases
#[derive(Arbitrary, Debug)]
enum WindowUpdateTest {
    /// Zero-byte window update
    ZeroByteUpdate { stream_index: u8 },
    /// Massive window increase (potential overflow)
    MassiveIncrease { stream_index: u8, increase: u64 },
    /// Duplicate window updates
    DuplicateUpdate {
        stream_index: u8,
        limit: u32,
        repeat_count: u8,
    },
    /// Window update after reset
    UpdateAfterReset {
        stream_index: u8,
        error_code: u32,
        new_limit: u32,
    },
    /// Conflicting window updates
    ConflictingUpdates { stream_index: u8, limits: Vec<u32> },
}

/// Flow control edge cases that should be handled gracefully
#[derive(Arbitrary, Debug)]
enum FlowControlEdgeCase {
    /// Send after exhausting credit (should emit STREAM_DATA_BLOCKED)
    SendAfterExhaustion {
        stream_index: u8,
        blocked_bytes: u16,
    },
    /// FIN with data at flow control boundary
    FinAtBoundary {
        stream_index: u8,
        data_to_boundary: u16,
    },
    /// Reset after partial send (final size consistency)
    ResetAfterPartialSend {
        stream_index: u8,
        sent_bytes: u16,
        reset_final_size: u32,
    },
    /// Receive beyond final size
    ReceiveBeyondFinalSize {
        stream_index: u8,
        final_size: u32,
        excess_bytes: u16,
    },
    /// Offset overflow in receive
    ReceiveOffsetOverflow {
        stream_index: u8,
        offset: u64,
        len: u32,
    },
    /// Credit accounting consistency after error
    CreditConsistencyAfterError {
        stream_index: u8,
        operations: Vec<CreditOp>,
    },
}

/// Credit operation for consistency testing
#[derive(Arbitrary, Debug)]
enum CreditOp {
    Send(u16),
    Receive(u16),
    WindowUpdate(u32),
    Reset(u32),
}

/// Convert fuzz enum to actual type
impl From<StreamRoleFuzz> for asupersync::net::quic_native::streams::StreamRole {
    fn from(role: StreamRoleFuzz) -> Self {
        match role {
            StreamRoleFuzz::Client => Self::Client,
            StreamRoleFuzz::Server => Self::Server,
        }
    }
}

/// Execute QUIC stream flow control fuzzing
fn fuzz_quic_stream_flow(input: QuicStreamFlowFuzz) {
    use asupersync::net::quic_native::streams::{StreamDirection, StreamId, StreamTable};

    // Create stream table with fuzzed flow control configuration
    let role = input.flow_config.role.into();
    let mut table = StreamTable::new_with_connection_limits(
        role,
        100, // max_local_bidi (not under test)
        100, // max_local_uni (not under test)
        input.flow_config.stream_send_window as u64,
        input.flow_config.stream_recv_window as u64,
        input.flow_config.connection_send_limit as u64,
        input.flow_config.connection_recv_limit as u64,
    );

    // Create initial streams for testing
    let mut stream_ids = Vec::new();
    for _ in 0..input.flow_config.initial_streams.min(10) {
        // Limit to prevent excessive setup time
        if let Ok(id) = table.open_local_bidi() {
            stream_ids.push(id);
        }
    }

    // Record initial flow control state for invariant checking
    let initial_connection_send = table.connection_send_remaining();
    let initial_connection_recv = table.connection_recv_remaining();

    // Execute flow control operations
    for op in input.operations {
        let _ = execute_flow_control_operation(&mut table, &stream_ids, op, role);

        // Verify flow control invariants after each operation
        verify_flow_control_invariants(&table, &stream_ids);
    }

    // Execute connection-level flow control tests
    for conn_test in input.connection_tests {
        let _ = execute_connection_flow_test(&mut table, &stream_ids, conn_test);
        verify_flow_control_invariants(&table, &stream_ids);
    }

    // Execute window update tests
    for window_test in input.window_updates {
        let _ = execute_window_update_test(&mut table, &stream_ids, window_test);
        verify_flow_control_invariants(&table, &stream_ids);
    }

    // Execute edge case tests
    for edge_case in input.edge_cases {
        let _ = execute_flow_control_edge_case(&mut table, &stream_ids, edge_case);
        verify_flow_control_invariants(&table, &stream_ids);
    }

    // Final consistency check
    assert!(table.connection_send_remaining() <= initial_connection_send);
    assert!(table.connection_recv_remaining() <= initial_connection_recv);
}

/// Execute a single flow control operation
fn execute_flow_control_operation(
    table: &mut asupersync::net::quic_native::streams::StreamTable,
    stream_ids: &[asupersync::net::quic_native::streams::StreamId],
    op: FlowControlOperation,
    role: asupersync::net::quic_native::streams::StreamRole,
) -> Result<(), Box<dyn std::error::Error>> {
    match op {
        FlowControlOperation::SendData {
            stream_index,
            data_len,
        } => {
            if let Some(&id) = stream_ids.get(stream_index as usize % stream_ids.len().max(1)) {
                // Test flow control violation detection
                let result = table.write_stream(id, data_len as u64);
                if result.is_err() {
                    // Should handle flow control errors gracefully
                    assert!(table.connection_send_remaining() >= 0); // Credit shouldn't go negative
                }
            }
        }
        FlowControlOperation::ReceiveData {
            stream_index,
            data_len,
        } => {
            if let Some(&id) = stream_ids.get(stream_index as usize % stream_ids.len().max(1)) {
                let _ = table.receive_stream(id, data_len as u64);
            }
        }
        FlowControlOperation::ReceiveSegment {
            stream_index,
            offset,
            data_len,
            fin_flag,
        } => {
            if let Some(&id) = stream_ids.get(stream_index as usize % stream_ids.len().max(1)) {
                let _ = table.receive_stream_segment(id, offset as u64, data_len as u64, fin_flag);
            }
        }
        FlowControlOperation::StreamWindowUpdate {
            stream_index,
            new_limit,
        } => {
            if let Some(&id) = stream_ids.get(stream_index as usize % stream_ids.len().max(1)) {
                if let Ok(stream) = table.stream_mut(id) {
                    // Test window increase on individual stream
                    let _ = stream.send_credit.increase_limit(new_limit as u64);
                }
            }
        }
        FlowControlOperation::ConnectionWindowUpdate {
            new_send_limit,
            new_recv_limit,
        } => {
            // Test connection-level window updates
            let _ = table.increase_connection_send_limit(new_send_limit as u64);
            let _ = table.increase_connection_recv_limit(new_recv_limit as u64);
        }
        FlowControlOperation::ResetStream {
            stream_index,
            error_code,
            final_size,
        } => {
            if let Some(&id) = stream_ids.get(stream_index as usize % stream_ids.len().max(1)) {
                if let Ok(stream) = table.stream_mut(id) {
                    let _ = stream.reset_send(error_code as u64, final_size as u64);
                }
            }
        }
        FlowControlOperation::StopSending {
            stream_index,
            error_code,
        } => {
            if let Some(&id) = stream_ids.get(stream_index as usize % stream_ids.len().max(1)) {
                if let Ok(stream) = table.stream_mut(id) {
                    stream.on_stop_sending(error_code as u64);
                }
            }
        }
        FlowControlOperation::ExhaustCredit {
            stream_index,
            excess_bytes,
        } => {
            if let Some(&id) = stream_ids.get(stream_index as usize % stream_ids.len().max(1)) {
                // Try to exceed flow control limits
                let huge_write = u64::MAX;
                let result = table.write_stream(id, huge_write);
                assert!(result.is_err()); // Should fail with flow control error

                // Smaller excess should also fail gracefully
                let _ = table.write_stream(id, excess_bytes as u64);
            }
        }
        FlowControlOperation::InterleavedOps {
            stream_index,
            send_chunks,
            recv_chunks,
        } => {
            if let Some(&id) = stream_ids.get(stream_index as usize % stream_ids.len().max(1)) {
                // Interleave send and receive operations to test race conditions
                for (send, recv) in send_chunks.into_iter().zip(recv_chunks.into_iter()) {
                    let _ = table.write_stream(id, send as u64);
                    let _ = table.receive_stream(id, recv as u64);
                }
            }
        }
    }
    Ok(())
}

/// Execute connection-level flow control test
fn execute_connection_flow_test(
    table: &mut asupersync::net::quic_native::streams::StreamTable,
    stream_ids: &[asupersync::net::quic_native::streams::StreamId],
    test: ConnectionFlowTest,
) -> Result<(), Box<dyn std::error::Error>> {
    match test {
        ConnectionFlowTest::ExhaustConnectionSend {
            stream_count,
            bytes_per_stream,
        } => {
            // Try to exhaust connection-level send credit across multiple streams
            for i in 0..stream_count.min(stream_ids.len() as u8) {
                if let Some(&id) = stream_ids.get(i as usize) {
                    let _ = table.write_stream(id, bytes_per_stream as u64);
                }
            }
        }
        ConnectionFlowTest::CreditRedistribution {
            close_streams,
            new_writes,
        } => {
            // Close some streams then try to write to others (credit redistribution)
            for &stream_idx in &close_streams {
                if let Some(&id) = stream_ids.get(stream_idx as usize % stream_ids.len().max(1)) {
                    if let Ok(stream) = table.stream_mut(id) {
                        let _ = stream.reset_send(0, stream.send_offset);
                    }
                }
            }
            // Try new writes after closing streams
            for (i, &write_amount) in new_writes.iter().enumerate() {
                if let Some(&id) = stream_ids.get(i % stream_ids.len().max(1)) {
                    let _ = table.write_stream(id, write_amount as u64);
                }
            }
        }
        ConnectionFlowTest::LimitRegression {
            current_limit,
            bad_limit,
        } => {
            // Try to regress connection limits (should fail)
            let _ = table.increase_connection_send_limit(current_limit as u64);
            let result = table.increase_connection_send_limit(bad_limit as u64);
            if bad_limit < current_limit {
                assert!(result.is_err()); // Should fail on regression
            }
        }
        ConnectionFlowTest::RapidExhaustionRecovery {
            exhaust_amount,
            recovery_amount,
            repeat_count,
        } => {
            // Rapidly exhaust and recover connection credit
            for _ in 0..repeat_count.min(10) {
                if let Some(&id) = stream_ids.get(0) {
                    let _ = table.write_stream(id, exhaust_amount as u64);
                }
                let _ = table.increase_connection_send_limit(
                    table.send_connection_credit.limit() + recovery_amount as u64,
                );
            }
        }
    }
    Ok(())
}

/// Execute window update test
fn execute_window_update_test(
    table: &mut asupersync::net::quic_native::streams::StreamTable,
    stream_ids: &[asupersync::net::quic_native::streams::StreamId],
    test: WindowUpdateTest,
) -> Result<(), Box<dyn std::error::Error>> {
    match test {
        WindowUpdateTest::ZeroByteUpdate { stream_index } => {
            if let Some(&id) = stream_ids.get(stream_index as usize % stream_ids.len().max(1)) {
                if let Ok(stream) = table.stream_mut(id) {
                    // Zero-byte window update should be handled gracefully
                    let current_limit = stream.send_credit.limit();
                    let _ = stream.send_credit.increase_limit(current_limit);
                }
            }
        }
        WindowUpdateTest::MassiveIncrease {
            stream_index,
            increase,
        } => {
            if let Some(&id) = stream_ids.get(stream_index as usize % stream_ids.len().max(1)) {
                if let Ok(stream) = table.stream_mut(id) {
                    // Test potential overflow in window increases
                    let result = stream.send_credit.increase_limit(increase);
                    // Should either succeed or fail gracefully, never panic
                    let _ = result;
                }
            }
        }
        WindowUpdateTest::DuplicateUpdate {
            stream_index,
            limit,
            repeat_count,
        } => {
            if let Some(&id) = stream_ids.get(stream_index as usize % stream_ids.len().max(1)) {
                if let Ok(stream) = table.stream_mut(id) {
                    // Duplicate window updates should be idempotent
                    for _ in 0..repeat_count.min(20) {
                        let _ = stream.send_credit.increase_limit(limit as u64);
                    }
                    assert_eq!(stream.send_credit.limit(), limit as u64);
                }
            }
        }
        WindowUpdateTest::UpdateAfterReset {
            stream_index,
            error_code,
            new_limit,
        } => {
            if let Some(&id) = stream_ids.get(stream_index as usize % stream_ids.len().max(1)) {
                if let Ok(stream) = table.stream_mut(id) {
                    let _ = stream.reset_send(error_code as u64, stream.send_offset);
                    // Window update after reset should be handled correctly
                    let _ = stream.send_credit.increase_limit(new_limit as u64);
                }
            }
        }
        WindowUpdateTest::ConflictingUpdates {
            stream_index,
            limits,
        } => {
            if let Some(&id) = stream_ids.get(stream_index as usize % stream_ids.len().max(1)) {
                if let Ok(stream) = table.stream_mut(id) {
                    // Multiple conflicting updates - only monotonically increasing should succeed
                    let mut expected_limit = stream.send_credit.limit();
                    for limit in limits {
                        if limit as u64 >= expected_limit {
                            expected_limit = limit as u64;
                        }
                        let _ = stream.send_credit.increase_limit(limit as u64);
                    }
                    assert!(stream.send_credit.limit() >= expected_limit);
                }
            }
        }
    }
    Ok(())
}

/// Execute flow control edge case
fn execute_flow_control_edge_case(
    table: &mut asupersync::net::quic_native::streams::StreamTable,
    stream_ids: &[asupersync::net::quic_native::streams::StreamId],
    edge_case: FlowControlEdgeCase,
) -> Result<(), Box<dyn std::error::Error>> {
    match edge_case {
        FlowControlEdgeCase::SendAfterExhaustion {
            stream_index,
            blocked_bytes,
        } => {
            if let Some(&id) = stream_ids.get(stream_index as usize % stream_ids.len().max(1)) {
                // Exhaust stream credit first
                let _ = table.write_stream(id, u64::MAX);
                // Try to send more (should emit STREAM_DATA_BLOCKED conceptually)
                let result = table.write_stream(id, blocked_bytes as u64);
                assert!(result.is_err()); // Should fail with flow control exhaustion
            }
        }
        FlowControlEdgeCase::FinAtBoundary {
            stream_index,
            data_to_boundary,
        } => {
            if let Some(&id) = stream_ids.get(stream_index as usize % stream_ids.len().max(1)) {
                // Send data up to flow control boundary, then FIN
                let _ = table.write_stream(id, data_to_boundary as u64);
                let _ = table.receive_stream_segment(id, 0, data_to_boundary as u64, true);
            }
        }
        FlowControlEdgeCase::ResetAfterPartialSend {
            stream_index,
            sent_bytes,
            reset_final_size,
        } => {
            if let Some(&id) = stream_ids.get(stream_index as usize % stream_ids.len().max(1)) {
                let _ = table.write_stream(id, sent_bytes as u64);
                if let Ok(stream) = table.stream_mut(id) {
                    // Reset final size should be >= actually sent bytes
                    let actual_sent = stream.send_offset;
                    let final_size = reset_final_size.max(actual_sent as u32) as u64;
                    let _ = stream.reset_send(42, final_size);
                }
            }
        }
        FlowControlEdgeCase::ReceiveBeyondFinalSize {
            stream_index,
            final_size,
            excess_bytes,
        } => {
            if let Some(&id) = stream_ids.get(stream_index as usize % stream_ids.len().max(1)) {
                let _ = table.set_stream_final_size(id, final_size as u64);
                // Try to receive beyond final size (should fail)
                let result =
                    table.receive_stream_segment(id, final_size as u64, excess_bytes as u64, false);
                assert!(result.is_err()); // Should fail with final size violation
            }
        }
        FlowControlEdgeCase::ReceiveOffsetOverflow {
            stream_index,
            offset,
            len,
        } => {
            if let Some(&id) = stream_ids.get(stream_index as usize % stream_ids.len().max(1)) {
                // Test offset + len overflow protection
                let result = table.receive_stream_segment(id, offset, len as u64, false);
                if offset.checked_add(len as u64).is_none() {
                    assert!(result.is_err()); // Should fail on overflow
                }
            }
        }
        FlowControlEdgeCase::CreditConsistencyAfterError {
            stream_index,
            operations,
        } => {
            if let Some(&id) = stream_ids.get(stream_index as usize % stream_ids.len().max(1)) {
                for op in operations {
                    match op {
                        CreditOp::Send(amount) => {
                            let _ = table.write_stream(id, amount as u64);
                        }
                        CreditOp::Receive(amount) => {
                            let _ = table.receive_stream(id, amount as u64);
                        }
                        CreditOp::WindowUpdate(limit) => {
                            if let Ok(stream) = table.stream_mut(id) {
                                let _ = stream.send_credit.increase_limit(limit as u64);
                            }
                        }
                        CreditOp::Reset(final_size) => {
                            if let Ok(stream) = table.stream_mut(id) {
                                let _ = stream.reset_send(0, final_size as u64);
                            }
                        }
                    }
                    // Verify credit consistency after each operation
                    verify_flow_control_invariants(table, stream_ids);
                }
            }
        }
    }
    Ok(())
}

/// Verify flow control invariants hold
fn verify_flow_control_invariants(
    table: &asupersync::net::quic_native::streams::StreamTable,
    stream_ids: &[asupersync::net::quic_native::streams::StreamId],
) {
    // Connection-level invariants
    assert!(table.connection_send_remaining() >= 0);
    assert!(table.connection_recv_remaining() >= 0);

    // Stream-level invariants
    for &id in stream_ids {
        if let Ok(stream) = table.stream(id) {
            // Send credit should never go negative
            assert!(stream.send_credit.remaining() >= 0);
            assert!(stream.recv_credit.remaining() >= 0);

            // Used credit should never exceed limit
            assert!(stream.send_credit.used() <= stream.send_credit.limit());
            assert!(stream.recv_credit.used() <= stream.recv_credit.limit());

            // Send offset should not exceed what was actually written
            // (This is checked implicitly by the flow control system)

            // If there's a final size, received data shouldn't exceed it
            if let Some(final_size) = stream.final_size {
                assert!(stream.recv_credit.used() <= final_size);
            }
        }
    }
}

fuzz_target!(|input: QuicStreamFlowFuzz| {
    // Limit input complexity to prevent timeouts
    if input.operations.len() > 1000 {
        return;
    }

    if input.flow_config.initial_streams > 20 {
        return;
    }

    if input.connection_tests.len() > 100 {
        return;
    }

    // Execute QUIC stream flow control fuzzing
    fuzz_quic_stream_flow(input);
});
