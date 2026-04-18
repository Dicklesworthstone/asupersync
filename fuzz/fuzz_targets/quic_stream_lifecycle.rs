#![no_main]

use libfuzzer_sys::fuzz_target;
use arbitrary::Arbitrary;

/// Fuzzing input for QUIC stream lifecycle and state machine
#[derive(Arbitrary, Debug)]
struct QuicStreamLifecycleFuzz {
    /// Initial stream table configuration
    table_config: StreamTableConfig,
    /// Sequence of stream operations to execute
    operations: Vec<StreamOperation>,
    /// Concurrent operations for race condition testing
    concurrent_ops: Vec<ConcurrentStreamOps>,
    /// Flow control stress tests
    flow_control_tests: Vec<FlowControlTest>,
    /// Edge case scenarios
    edge_cases: Vec<StreamEdgeCase>,
}

/// Stream table configuration for fuzzing different setups
#[derive(Arbitrary, Debug)]
struct StreamTableConfig {
    /// Endpoint role
    role: StreamRoleFuzz,
    /// Maximum local bidirectional streams
    max_local_bidi: u16,
    /// Maximum local unidirectional streams
    max_local_uni: u16,
    /// Per-stream send window
    send_window: u32,
    /// Per-stream receive window
    recv_window: u32,
    /// Connection-level send limit
    connection_send_limit: u32,
    /// Connection-level receive limit
    connection_recv_limit: u32,
}

/// Stream role for fuzzing
#[derive(Arbitrary, Debug, Clone, Copy)]
enum StreamRoleFuzz {
    Client,
    Server,
}

/// Stream operations to fuzz the state machine
#[derive(Arbitrary, Debug)]
enum StreamOperation {
    /// Open local bidirectional stream
    OpenLocalBidi,
    /// Open local unidirectional stream
    OpenLocalUni,
    /// Accept remote stream with given ID pattern
    AcceptRemote {
        id_base: u16,
        direction: StreamDirectionFuzz,
    },
    /// Write data to stream
    Write {
        stream_index: u8,
        data_len: u16,
    },
    /// Receive data on stream
    Receive {
        stream_index: u8,
        data_len: u16,
    },
    /// Receive out-of-order data
    ReceiveSegment {
        stream_index: u8,
        offset: u32,
        data_len: u16,
        is_fin: bool,
    },
    /// Reset stream
    ResetStream {
        stream_index: u8,
        error_code: u32,
        final_size: u32,
    },
    /// Stop sending on stream
    StopSending {
        stream_index: u8,
        error_code: u32,
    },
    /// Set final size
    SetFinalSize {
        stream_index: u8,
        final_size: u32,
    },
    /// Increase connection flow control limits
    IncreaseConnectionLimits {
        send_limit: u32,
        recv_limit: u32,
    },
    /// Round-robin iteration test
    TestRoundRobin {
        iterations: u8,
    },
    /// Close random streams
    CloseRandomStreams {
        count: u8,
    },
}

/// Stream direction for fuzzing
#[derive(Arbitrary, Debug, Clone, Copy)]
enum StreamDirectionFuzz {
    Bidirectional,
    Unidirectional,
}

/// Concurrent operations for race condition testing
#[derive(Arbitrary, Debug)]
struct ConcurrentStreamOps {
    /// Operations to execute "simultaneously"
    ops: Vec<StreamOperation>,
    /// Whether to interleave operations
    interleave: bool,
}

/// Flow control stress testing scenarios
#[derive(Arbitrary, Debug)]
enum FlowControlTest {
    /// Exhaust stream credit
    ExhaustStreamCredit {
        stream_index: u8,
        excess_amount: u16,
    },
    /// Exhaust connection credit
    ExhaustConnectionCredit {
        total_writes: u8,
    },
    /// Credit release and reuse
    CreditReleaseReuse {
        stream_index: u8,
        write_amount: u16,
        release_amount: u16,
    },
    /// Limit regression attempts
    LimitRegression {
        original_limit: u32,
        regressed_limit: u32,
    },
    /// Flow control race conditions
    FlowControlRace {
        operations: Vec<FlowControlOp>,
    },
}

/// Flow control operation
#[derive(Arbitrary, Debug)]
enum FlowControlOp {
    Write { stream_idx: u8, len: u16 },
    Receive { stream_idx: u8, len: u16 },
    IncreaseLimit { stream_idx: u8, new_limit: u32 },
    Release { stream_idx: u8, amount: u16 },
}

/// Edge cases for stream state machine testing
#[derive(Arbitrary, Debug)]
enum StreamEdgeCase {
    /// Duplicate stream ID collision
    DuplicateStreamId { id_pattern: u16 },
    /// Invalid stream ID for role
    InvalidStreamIdForRole { id_pattern: u16 },
    /// Write after reset
    WriteAfterReset { stream_index: u8 },
    /// Receive after stop
    ReceiveAfterStop { stream_index: u8 },
    /// Inconsistent reset final size
    InconsistentResetFinalSize {
        stream_index: u8,
        first_final_size: u32,
        second_final_size: u32,
    },
    /// Offset overflow
    OffsetOverflow {
        stream_index: u8,
        offset: u64,
        len: u64,
    },
    /// Final size violation
    FinalSizeViolation {
        stream_index: u8,
        final_size: u32,
        excess_data: u16,
    },
    /// Range merging stress test
    RangeMergingStress {
        stream_index: u8,
        ranges: Vec<(u32, u16)>, // (offset, length) pairs
    },
}

/// Convert fuzz enums to actual types
impl From<StreamRoleFuzz> for asupersync::net::quic_native::streams::StreamRole {
    fn from(role: StreamRoleFuzz) -> Self {
        match role {
            StreamRoleFuzz::Client => Self::Client,
            StreamRoleFuzz::Server => Self::Server,
        }
    }
}

impl From<StreamDirectionFuzz> for asupersync::net::quic_native::streams::StreamDirection {
    fn from(dir: StreamDirectionFuzz) -> Self {
        match dir {
            StreamDirectionFuzz::Bidirectional => Self::Bidirectional,
            StreamDirectionFuzz::Unidirectional => Self::Unidirectional,
        }
    }
}

/// Execute stream lifecycle fuzzing
fn fuzz_stream_lifecycle(input: QuicStreamLifecycleFuzz) {
    use asupersync::net::quic_native::streams::StreamTable;

    // Create stream table with fuzzed configuration
    let role = input.table_config.role.into();
    let mut table = StreamTable::new_with_connection_limits(
        role,
        input.table_config.max_local_bidi as u64,
        input.table_config.max_local_uni as u64,
        input.table_config.send_window as u64,
        input.table_config.recv_window as u64,
        input.table_config.connection_send_limit as u64,
        input.table_config.connection_recv_limit as u64,
    );

    // Track opened streams for operation indexing
    let mut stream_ids = Vec::new();

    // Execute basic operations
    for op in input.operations {
        let _ = execute_stream_operation(&mut table, &mut stream_ids, op, role);
    }

    // Execute concurrent operations (simulated)
    for concurrent_test in input.concurrent_ops {
        if concurrent_test.interleave {
            // Interleave operations to test race conditions
            for (i, op) in concurrent_test.ops.into_iter().enumerate() {
                if i % 2 == 0 {
                    let _ = execute_stream_operation(&mut table, &mut stream_ids, op, role);
                } else {
                    // Simulate delay by doing some other operation first
                    let _ = table.len();
                    let _ = execute_stream_operation(&mut table, &mut stream_ids, op, role);
                }
            }
        } else {
            // Execute all operations in sequence
            for op in concurrent_test.ops {
                let _ = execute_stream_operation(&mut table, &mut stream_ids, op, role);
            }
        }
    }

    // Execute flow control stress tests
    for flow_test in input.flow_control_tests {
        let _ = execute_flow_control_test(&mut table, &stream_ids, flow_test);
    }

    // Execute edge case tests
    for edge_case in input.edge_cases {
        let _ = execute_edge_case_test(&mut table, &mut stream_ids, edge_case, role);
    }

    // Final validation: table should be in consistent state
    let _ = table.len();
    let _ = table.is_empty();
    let _ = table.connection_send_remaining();
    let _ = table.connection_recv_remaining();

    // Test round-robin functionality
    let mut rr_count = 0;
    while let Some(_stream_id) = table.next_writable_stream() {
        rr_count += 1;
        if rr_count > 100 { // Prevent infinite loops
            break;
        }
    }
}

/// Execute a single stream operation
fn execute_stream_operation(
    table: &mut asupersync::net::quic_native::streams::StreamTable,
    stream_ids: &mut Vec<asupersync::net::quic_native::streams::StreamId>,
    op: StreamOperation,
    role: asupersync::net::quic_native::streams::StreamRole,
) -> Result<(), Box<dyn std::error::Error>> {
    use asupersync::net::quic_native::streams::{StreamId, StreamDirection};

    match op {
        StreamOperation::OpenLocalBidi => {
            if let Ok(id) = table.open_local_bidi() {
                stream_ids.push(id);
            }
        }
        StreamOperation::OpenLocalUni => {
            if let Ok(id) = table.open_local_uni() {
                stream_ids.push(id);
            }
        }
        StreamOperation::AcceptRemote { id_base, direction } => {
            // Generate a remote stream ID
            let remote_role = match role {
                asupersync::net::quic_native::streams::StreamRole::Client =>
                    asupersync::net::quic_native::streams::StreamRole::Server,
                asupersync::net::quic_native::streams::StreamRole::Server =>
                    asupersync::net::quic_native::streams::StreamRole::Client,
            };
            let id = StreamId::local(remote_role, direction.into(), id_base as u64);
            if let Ok(_) = table.accept_remote_stream(id) {
                stream_ids.push(id);
            }
        }
        StreamOperation::Write { stream_index, data_len } => {
            if let Some(&id) = stream_ids.get(stream_index as usize % stream_ids.len().max(1)) {
                let _ = table.write_stream(id, data_len as u64);
            }
        }
        StreamOperation::Receive { stream_index, data_len } => {
            if let Some(&id) = stream_ids.get(stream_index as usize % stream_ids.len().max(1)) {
                let _ = table.receive_stream(id, data_len as u64);
            }
        }
        StreamOperation::ReceiveSegment { stream_index, offset, data_len, is_fin } => {
            if let Some(&id) = stream_ids.get(stream_index as usize % stream_ids.len().max(1)) {
                let _ = table.receive_stream_segment(id, offset as u64, data_len as u64, is_fin);
            }
        }
        StreamOperation::ResetStream { stream_index, error_code, final_size } => {
            if let Some(&id) = stream_ids.get(stream_index as usize % stream_ids.len().max(1)) {
                if let Ok(stream) = table.stream_mut(id) {
                    let _ = stream.reset_send(error_code as u64, final_size as u64);
                }
            }
        }
        StreamOperation::StopSending { stream_index, error_code } => {
            if let Some(&id) = stream_ids.get(stream_index as usize % stream_ids.len().max(1)) {
                if let Ok(stream) = table.stream_mut(id) {
                    stream.on_stop_sending(error_code as u64);
                }
            }
        }
        StreamOperation::SetFinalSize { stream_index, final_size } => {
            if let Some(&id) = stream_ids.get(stream_index as usize % stream_ids.len().max(1)) {
                let _ = table.set_stream_final_size(id, final_size as u64);
            }
        }
        StreamOperation::IncreaseConnectionLimits { send_limit, recv_limit } => {
            let _ = table.increase_connection_send_limit(send_limit as u64);
            let _ = table.increase_connection_recv_limit(recv_limit as u64);
        }
        StreamOperation::TestRoundRobin { iterations } => {
            for _ in 0..iterations.min(50) { // Cap iterations to prevent timeouts
                let _ = table.next_writable_stream();
            }
        }
        StreamOperation::CloseRandomStreams { count } => {
            let to_remove = count.min(stream_ids.len() as u8);
            for _ in 0..to_remove {
                if !stream_ids.is_empty() {
                    stream_ids.remove(0);
                }
            }
        }
    }
    Ok(())
}

/// Execute flow control stress test
fn execute_flow_control_test(
    table: &mut asupersync::net::quic_native::streams::StreamTable,
    stream_ids: &[asupersync::net::quic_native::streams::StreamId],
    test: FlowControlTest,
) -> Result<(), Box<dyn std::error::Error>> {
    match test {
        FlowControlTest::ExhaustStreamCredit { stream_index, excess_amount } => {
            if let Some(&id) = stream_ids.get(stream_index as usize % stream_ids.len().max(1)) {
                // Try to write more than the stream's credit
                let _ = table.write_stream(id, u64::MAX);
                let _ = table.write_stream(id, excess_amount as u64);
            }
        }
        FlowControlTest::ExhaustConnectionCredit { total_writes } => {
            // Try to exhaust connection-level credit
            for i in 0..total_writes.min(50) {
                if let Some(&id) = stream_ids.get(i as usize % stream_ids.len().max(1)) {
                    let _ = table.write_stream(id, 1000);
                }
            }
        }
        FlowControlTest::CreditReleaseReuse { stream_index, write_amount, release_amount } => {
            if let Some(&id) = stream_ids.get(stream_index as usize % stream_ids.len().max(1)) {
                let _ = table.write_stream(id, write_amount as u64);
                // Note: Credit release would be tested if the API exposed it
                let _ = table.write_stream(id, release_amount as u64);
            }
        }
        FlowControlTest::LimitRegression { original_limit, regressed_limit } => {
            let _ = table.increase_connection_send_limit(original_limit as u64);
            // Try to regress the limit (should fail)
            let _ = table.increase_connection_send_limit(regressed_limit as u64);
        }
        FlowControlTest::FlowControlRace { operations } => {
            for op in operations {
                match op {
                    FlowControlOp::Write { stream_idx, len } => {
                        if let Some(&id) = stream_ids.get(stream_idx as usize % stream_ids.len().max(1)) {
                            let _ = table.write_stream(id, len as u64);
                        }
                    }
                    FlowControlOp::Receive { stream_idx, len } => {
                        if let Some(&id) = stream_ids.get(stream_idx as usize % stream_ids.len().max(1)) {
                            let _ = table.receive_stream(id, len as u64);
                        }
                    }
                    FlowControlOp::IncreaseLimit { stream_idx: _, new_limit } => {
                        let _ = table.increase_connection_send_limit(new_limit as u64);
                    }
                    FlowControlOp::Release { stream_idx: _, amount: _ } => {
                        // Credit release would be tested if exposed by API
                    }
                }
            }
        }
    }
    Ok(())
}

/// Execute edge case test
fn execute_edge_case_test(
    table: &mut asupersync::net::quic_native::streams::StreamTable,
    stream_ids: &mut Vec<asupersync::net::quic_native::streams::StreamId>,
    edge_case: StreamEdgeCase,
    role: asupersync::net::quic_native::streams::StreamRole,
) -> Result<(), Box<dyn std::error::Error>> {
    use asupersync::net::quic_native::streams::{StreamId, StreamDirection};

    match edge_case {
        StreamEdgeCase::DuplicateStreamId { id_pattern } => {
            let id = StreamId::local(role, StreamDirection::Bidirectional, id_pattern as u64);
            // Try to accept the same remote stream twice
            let _ = table.accept_remote_stream(id);
            let _ = table.accept_remote_stream(id); // Should fail
        }
        StreamEdgeCase::InvalidStreamIdForRole { id_pattern } => {
            // Try to accept a locally-initiated stream as remote
            let id = StreamId::local(role, StreamDirection::Bidirectional, id_pattern as u64);
            let _ = table.accept_remote_stream(id); // Should fail
        }
        StreamEdgeCase::WriteAfterReset { stream_index } => {
            if let Some(&id) = stream_ids.get(stream_index as usize % stream_ids.len().max(1)) {
                if let Ok(stream) = table.stream_mut(id) {
                    let _ = stream.reset_send(42, 0);
                }
                let _ = table.write_stream(id, 100); // Should fail
            }
        }
        StreamEdgeCase::ReceiveAfterStop { stream_index } => {
            if let Some(&id) = stream_ids.get(stream_index as usize % stream_ids.len().max(1)) {
                if let Ok(stream) = table.stream_mut(id) {
                    stream.stop_receiving(42);
                }
                let _ = table.receive_stream(id, 100); // Should fail
            }
        }
        StreamEdgeCase::InconsistentResetFinalSize {
            stream_index,
            first_final_size,
            second_final_size
        } => {
            if let Some(&id) = stream_ids.get(stream_index as usize % stream_ids.len().max(1)) {
                if let Ok(stream) = table.stream_mut(id) {
                    let _ = stream.reset_send(42, first_final_size as u64);
                    let _ = stream.reset_send(42, second_final_size as u64); // Should fail if different
                }
            }
        }
        StreamEdgeCase::OffsetOverflow { stream_index, offset, len } => {
            if let Some(&id) = stream_ids.get(stream_index as usize % stream_ids.len().max(1)) {
                // Try to receive at an offset that would overflow
                let _ = table.receive_stream_segment(id, offset, len, false);
            }
        }
        StreamEdgeCase::FinalSizeViolation { stream_index, final_size, excess_data } => {
            if let Some(&id) = stream_ids.get(stream_index as usize % stream_ids.len().max(1)) {
                let _ = table.set_stream_final_size(id, final_size as u64);
                // Try to receive more data than the final size allows
                let _ = table.receive_stream_segment(
                    id,
                    final_size as u64,
                    excess_data as u64,
                    false
                );
            }
        }
        StreamEdgeCase::RangeMergingStress { stream_index, ranges } => {
            if let Some(&id) = stream_ids.get(stream_index as usize % stream_ids.len().max(1)) {
                // Send overlapping and adjacent ranges to stress-test merging logic
                for (offset, len) in ranges.into_iter().take(50) { // Limit to prevent timeouts
                    let _ = table.receive_stream_segment(id, offset as u64, len as u64, false);
                }
            }
        }
    }
    Ok(())
}

fuzz_target!(|input: QuicStreamLifecycleFuzz| {
    // Limit input complexity to prevent timeouts
    if input.operations.len() > 500 {
        return;
    }

    if input.table_config.max_local_bidi > 1000 || input.table_config.max_local_uni > 1000 {
        return;
    }

    if input.concurrent_ops.len() > 50 {
        return;
    }

    // Execute the stream lifecycle fuzzing
    fuzz_stream_lifecycle(input);
});