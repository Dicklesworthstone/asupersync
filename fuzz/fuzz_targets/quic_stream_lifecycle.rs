#![no_main]

use arbitrary::Arbitrary;
use asupersync::net::quic_native::streams::{
    FlowControlError, QuicStreamError, StreamId, StreamRole, StreamTable, StreamTableError,
};
use libfuzzer_sys::fuzz_target;

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
    Write { stream_index: u8, data_len: u16 },
    /// Receive data on stream
    Receive { stream_index: u8, data_len: u16 },
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
    StopSending { stream_index: u8, error_code: u32 },
    /// Set final size
    SetFinalSize { stream_index: u8, final_size: u32 },
    /// Increase connection flow control limits
    IncreaseConnectionLimits { send_limit: u32, recv_limit: u32 },
    /// Round-robin iteration test
    TestRoundRobin { iterations: u8 },
    /// Close random streams
    CloseRandomStreams { count: u8 },
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
    ExhaustConnectionCredit { total_writes: u8 },
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
    FlowControlRace { operations: Vec<FlowControlOp> },
}

/// Flow control operation
#[derive(Arbitrary, Debug)]
enum FlowControlOp {
    Write { stream_idx: u8, len: u16 },
    Receive { stream_idx: u8, len: u16 },
    IncreaseLimit { _stream_idx: u8, new_limit: u32 },
    Release { _stream_idx: u8, _amount: u16 },
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

fn observe_error(label: &str, error: &impl std::fmt::Display) {
    assert!(
        !error.to_string().is_empty(),
        "{label} errors should carry a diagnostic"
    );
}

fn observe_table_snapshot(table: &StreamTable) {
    let stream_count = table.len();
    assert_eq!(
        table.is_empty(),
        stream_count == 0,
        "stream-table emptiness must match len"
    );
}

fn observe_open_result(
    label: &str,
    table: &StreamTable,
    before_len: usize,
    stream_ids: &mut Vec<StreamId>,
    result: Result<StreamId, StreamTableError>,
) {
    match result {
        Ok(id) => {
            assert_eq!(
                table.len(),
                before_len + 1,
                "{label} should insert exactly one stream"
            );
            stream_ids.push(id);
        }
        Err(error) => observe_error(label, &error),
    }
}

fn observe_accept_remote_result(
    label: &str,
    table: &StreamTable,
    before_len: usize,
    stream_ids: &mut Vec<StreamId>,
    id: StreamId,
    result: Result<(), StreamTableError>,
) {
    match result {
        Ok(()) => {
            assert_eq!(
                table.len(),
                before_len + 1,
                "{label} should insert exactly one remote stream"
            );
            stream_ids.push(id);
        }
        Err(error) => observe_error(label, &error),
    }
}

fn observe_table_result(label: &str, result: Result<(), StreamTableError>) {
    if let Err(error) = result {
        observe_error(label, &error);
    }
}

fn observe_stream_result(label: &str, result: Result<(), QuicStreamError>) {
    if let Err(error) = result {
        observe_error(label, &error);
    }
}

fn observe_driver_result(label: &str, result: Result<(), Box<dyn std::error::Error>>) {
    if let Err(error) = result {
        observe_error(label, &error);
    }
}

fn observe_write_result(
    label: &str,
    table: &StreamTable,
    before_send_remaining: u64,
    result: Result<(), StreamTableError>,
) {
    match result {
        Ok(()) => assert!(
            table.connection_send_remaining() <= before_send_remaining,
            "{label} should not increase send credit while writing"
        ),
        Err(error) => observe_error(label, &error),
    }
}

fn observe_receive_result(
    label: &str,
    table: &StreamTable,
    before_recv_remaining: u64,
    result: Result<(), StreamTableError>,
) {
    match result {
        Ok(()) => assert!(
            table.connection_recv_remaining() <= before_recv_remaining,
            "{label} should not increase receive credit while receiving"
        ),
        Err(error) => observe_error(label, &error),
    }
}

fn observe_limit_result(
    label: &str,
    after_remaining: u64,
    before_remaining: u64,
    result: Result<(), FlowControlError>,
) {
    match result {
        Ok(()) => assert!(
            after_remaining >= before_remaining,
            "{label} should not reduce remaining connection credit"
        ),
        Err(error) => observe_error(label, &error),
    }
}

fn observe_next_writable(table: &mut StreamTable) {
    if let Some(stream_id) = table.next_writable_stream() {
        assert!(
            table.stream(stream_id).is_ok(),
            "round-robin returned an unknown writable stream"
        );
    }
}

/// Execute stream lifecycle fuzzing
fn fuzz_stream_lifecycle(input: QuicStreamLifecycleFuzz) {
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
        let result = execute_stream_operation(&mut table, &mut stream_ids, op, role);
        observe_driver_result("execute stream operation", result);
    }

    // Execute concurrent operations (simulated)
    for concurrent_test in input.concurrent_ops {
        if concurrent_test.interleave {
            // Interleave operations to test race conditions
            for (i, op) in concurrent_test.ops.into_iter().enumerate() {
                if i % 2 == 0 {
                    let result = execute_stream_operation(&mut table, &mut stream_ids, op, role);
                    observe_driver_result("execute interleaved stream operation", result);
                } else {
                    // Simulate delay by doing some other operation first
                    observe_table_snapshot(&table);
                    let result = execute_stream_operation(&mut table, &mut stream_ids, op, role);
                    observe_driver_result("execute delayed stream operation", result);
                }
            }
        } else {
            // Execute all operations in sequence
            for op in concurrent_test.ops {
                let result = execute_stream_operation(&mut table, &mut stream_ids, op, role);
                observe_driver_result("execute sequential stream operation", result);
            }
        }
    }

    // Execute flow control stress tests
    for flow_test in input.flow_control_tests {
        let result = execute_flow_control_test(&mut table, &stream_ids, flow_test);
        observe_driver_result("execute flow-control test", result);
    }

    // Execute edge case tests
    for edge_case in input.edge_cases {
        let result = execute_edge_case_test(&mut table, &mut stream_ids, edge_case, role);
        observe_driver_result("execute edge-case test", result);
    }

    // Final validation: table should be in consistent state
    observe_table_snapshot(&table);

    // Test round-robin functionality
    let mut rr_count = 0;
    while table.next_writable_stream().is_some() {
        rr_count += 1;
        if rr_count > 100 {
            // Prevent infinite loops
            break;
        }
    }
}

/// Execute a single stream operation
fn execute_stream_operation(
    table: &mut StreamTable,
    stream_ids: &mut Vec<StreamId>,
    op: StreamOperation,
    role: StreamRole,
) -> Result<(), Box<dyn std::error::Error>> {
    use asupersync::net::quic_native::streams::StreamId;

    match op {
        StreamOperation::OpenLocalBidi => {
            let before_len = table.len();
            let result = table.open_local_bidi();
            observe_open_result(
                "open local bidi stream",
                table,
                before_len,
                stream_ids,
                result,
            );
        }
        StreamOperation::OpenLocalUni => {
            let before_len = table.len();
            let result = table.open_local_uni();
            observe_open_result(
                "open local uni stream",
                table,
                before_len,
                stream_ids,
                result,
            );
        }
        StreamOperation::AcceptRemote { id_base, direction } => {
            // Generate a remote stream ID
            let remote_role = match role {
                StreamRole::Client => StreamRole::Server,
                StreamRole::Server => StreamRole::Client,
            };
            let id = StreamId::local(remote_role, direction.into(), id_base as u64);
            let before_len = table.len();
            let result = table.accept_remote_stream(id);
            observe_accept_remote_result(
                "accept remote stream",
                table,
                before_len,
                stream_ids,
                id,
                result,
            );
        }
        StreamOperation::Write {
            stream_index,
            data_len,
        } => {
            if let Some(&id) = stream_ids.get(stream_index as usize % stream_ids.len().max(1)) {
                let before_send_remaining = table.connection_send_remaining();
                let result = table.write_stream(id, data_len as u64);
                observe_write_result("write stream", table, before_send_remaining, result);
            }
        }
        StreamOperation::Receive {
            stream_index,
            data_len,
        } => {
            if let Some(&id) = stream_ids.get(stream_index as usize % stream_ids.len().max(1)) {
                let before_recv_remaining = table.connection_recv_remaining();
                let result = table.receive_stream(id, data_len as u64);
                observe_receive_result("receive stream", table, before_recv_remaining, result);
            }
        }
        StreamOperation::ReceiveSegment {
            stream_index,
            offset,
            data_len,
            is_fin,
        } => {
            if let Some(&id) = stream_ids.get(stream_index as usize % stream_ids.len().max(1)) {
                let before_recv_remaining = table.connection_recv_remaining();
                let result =
                    table.receive_stream_segment(id, offset as u64, data_len as u64, is_fin);
                observe_receive_result(
                    "receive stream segment",
                    table,
                    before_recv_remaining,
                    result,
                );
            }
        }
        StreamOperation::ResetStream {
            stream_index,
            error_code,
            final_size,
        } => {
            if let Some(&id) = stream_ids.get(stream_index as usize % stream_ids.len().max(1))
                && let Ok(stream) = table.stream_mut(id)
            {
                let result = stream.reset_send(error_code as u64, final_size as u64);
                observe_stream_result("reset stream send side", result);
            }
        }
        StreamOperation::StopSending {
            stream_index,
            error_code,
        } => {
            if let Some(&id) = stream_ids.get(stream_index as usize % stream_ids.len().max(1))
                && let Ok(stream) = table.stream_mut(id)
            {
                stream.on_stop_sending(error_code as u64);
            }
        }
        StreamOperation::SetFinalSize {
            stream_index,
            final_size,
        } => {
            if let Some(&id) = stream_ids.get(stream_index as usize % stream_ids.len().max(1)) {
                let result = table.set_stream_final_size(id, final_size as u64);
                observe_table_result("set stream final size", result);
            }
        }
        StreamOperation::IncreaseConnectionLimits {
            send_limit,
            recv_limit,
        } => {
            let before_send_remaining = table.connection_send_remaining();
            let send_result = table.increase_connection_send_limit(send_limit as u64);
            observe_limit_result(
                "increase connection send limit",
                table.connection_send_remaining(),
                before_send_remaining,
                send_result,
            );

            let before_recv_remaining = table.connection_recv_remaining();
            let recv_result = table.increase_connection_recv_limit(recv_limit as u64);
            observe_limit_result(
                "increase connection receive limit",
                table.connection_recv_remaining(),
                before_recv_remaining,
                recv_result,
            );
        }
        StreamOperation::TestRoundRobin { iterations } => {
            for _ in 0..iterations.min(50) {
                // Cap iterations to prevent timeouts
                observe_next_writable(table);
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
    table: &mut StreamTable,
    stream_ids: &[StreamId],
    test: FlowControlTest,
) -> Result<(), Box<dyn std::error::Error>> {
    match test {
        FlowControlTest::ExhaustStreamCredit {
            stream_index,
            excess_amount,
        } => {
            if let Some(&id) = stream_ids.get(stream_index as usize % stream_ids.len().max(1)) {
                // Try to write more than the stream's credit
                let before_send_remaining = table.connection_send_remaining();
                let max_result = table.write_stream(id, u64::MAX);
                observe_write_result(
                    "exhaust stream credit with max write",
                    table,
                    before_send_remaining,
                    max_result,
                );
                let before_send_remaining = table.connection_send_remaining();
                let excess_result = table.write_stream(id, excess_amount as u64);
                observe_write_result(
                    "exhaust stream credit with excess write",
                    table,
                    before_send_remaining,
                    excess_result,
                );
            }
        }
        FlowControlTest::ExhaustConnectionCredit { total_writes } => {
            // Try to exhaust connection-level credit
            for i in 0..total_writes.min(50) {
                if let Some(&id) = stream_ids.get(i as usize % stream_ids.len().max(1)) {
                    let before_send_remaining = table.connection_send_remaining();
                    let result = table.write_stream(id, 1000);
                    observe_write_result(
                        "exhaust connection credit write",
                        table,
                        before_send_remaining,
                        result,
                    );
                }
            }
        }
        FlowControlTest::CreditReleaseReuse {
            stream_index,
            write_amount,
            release_amount,
        } => {
            if let Some(&id) = stream_ids.get(stream_index as usize % stream_ids.len().max(1)) {
                let before_send_remaining = table.connection_send_remaining();
                let write_result = table.write_stream(id, write_amount as u64);
                observe_write_result(
                    "credit release reuse initial write",
                    table,
                    before_send_remaining,
                    write_result,
                );
                // Note: Credit release would be tested if the API exposed it
                let before_send_remaining = table.connection_send_remaining();
                let reuse_result = table.write_stream(id, release_amount as u64);
                observe_write_result(
                    "credit release reuse follow-up write",
                    table,
                    before_send_remaining,
                    reuse_result,
                );
            }
        }
        FlowControlTest::LimitRegression {
            original_limit,
            regressed_limit,
        } => {
            let before_send_remaining = table.connection_send_remaining();
            let original_result = table.increase_connection_send_limit(original_limit as u64);
            observe_limit_result(
                "original connection send limit",
                table.connection_send_remaining(),
                before_send_remaining,
                original_result,
            );
            // Try to regress the limit (should fail)
            let before_send_remaining = table.connection_send_remaining();
            let regressed_result = table.increase_connection_send_limit(regressed_limit as u64);
            observe_limit_result(
                "regressed connection send limit",
                table.connection_send_remaining(),
                before_send_remaining,
                regressed_result,
            );
        }
        FlowControlTest::FlowControlRace { operations } => {
            for op in operations {
                match op {
                    FlowControlOp::Write { stream_idx, len } => {
                        if let Some(&id) =
                            stream_ids.get(stream_idx as usize % stream_ids.len().max(1))
                        {
                            let before_send_remaining = table.connection_send_remaining();
                            let result = table.write_stream(id, len as u64);
                            observe_write_result(
                                "flow race write",
                                table,
                                before_send_remaining,
                                result,
                            );
                        }
                    }
                    FlowControlOp::Receive { stream_idx, len } => {
                        if let Some(&id) =
                            stream_ids.get(stream_idx as usize % stream_ids.len().max(1))
                        {
                            let before_recv_remaining = table.connection_recv_remaining();
                            let result = table.receive_stream(id, len as u64);
                            observe_receive_result(
                                "flow race receive",
                                table,
                                before_recv_remaining,
                                result,
                            );
                        }
                    }
                    FlowControlOp::IncreaseLimit {
                        _stream_idx: _,
                        new_limit,
                    } => {
                        let before_send_remaining = table.connection_send_remaining();
                        let result = table.increase_connection_send_limit(new_limit as u64);
                        observe_limit_result(
                            "flow race increase send limit",
                            table.connection_send_remaining(),
                            before_send_remaining,
                            result,
                        );
                    }
                    FlowControlOp::Release {
                        _stream_idx: _,
                        _amount: _,
                    } => {
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
    table: &mut StreamTable,
    stream_ids: &mut Vec<StreamId>,
    edge_case: StreamEdgeCase,
    role: StreamRole,
) -> Result<(), Box<dyn std::error::Error>> {
    use asupersync::net::quic_native::streams::{StreamDirection, StreamId};

    match edge_case {
        StreamEdgeCase::DuplicateStreamId { id_pattern } => {
            let id = StreamId::local(role, StreamDirection::Bidirectional, id_pattern as u64);
            // Try to accept the same remote stream twice
            let before_len = table.len();
            let first_result = table.accept_remote_stream(id);
            observe_accept_remote_result(
                "duplicate stream first accept",
                table,
                before_len,
                stream_ids,
                id,
                first_result,
            );
            let before_len = table.len();
            let second_result = table.accept_remote_stream(id);
            observe_accept_remote_result(
                "duplicate stream second accept",
                table,
                before_len,
                stream_ids,
                id,
                second_result,
            );
        }
        StreamEdgeCase::InvalidStreamIdForRole { id_pattern } => {
            // Try to accept a locally-initiated stream as remote
            let id = StreamId::local(role, StreamDirection::Bidirectional, id_pattern as u64);
            let before_len = table.len();
            let result = table.accept_remote_stream(id);
            observe_accept_remote_result(
                "invalid local stream accepted as remote",
                table,
                before_len,
                stream_ids,
                id,
                result,
            );
        }
        StreamEdgeCase::WriteAfterReset { stream_index } => {
            if let Some(&id) = stream_ids.get(stream_index as usize % stream_ids.len().max(1)) {
                if let Ok(stream) = table.stream_mut(id) {
                    let result = stream.reset_send(42, 0);
                    observe_stream_result("write-after-reset setup reset", result);
                }
                let before_send_remaining = table.connection_send_remaining();
                let result = table.write_stream(id, 100);
                observe_write_result("write after reset", table, before_send_remaining, result);
            }
        }
        StreamEdgeCase::ReceiveAfterStop { stream_index } => {
            if let Some(&id) = stream_ids.get(stream_index as usize % stream_ids.len().max(1)) {
                if let Ok(stream) = table.stream_mut(id) {
                    stream.stop_receiving(42);
                }
                let before_recv_remaining = table.connection_recv_remaining();
                let result = table.receive_stream(id, 100);
                observe_receive_result("receive after stop", table, before_recv_remaining, result);
            }
        }
        StreamEdgeCase::InconsistentResetFinalSize {
            stream_index,
            first_final_size,
            second_final_size,
        } => {
            if let Some(&id) = stream_ids.get(stream_index as usize % stream_ids.len().max(1))
                && let Ok(stream) = table.stream_mut(id)
            {
                let first_result = stream.reset_send(42, first_final_size as u64);
                observe_stream_result("inconsistent reset first final size", first_result);
                let second_result = stream.reset_send(42, second_final_size as u64);
                observe_stream_result("inconsistent reset second final size", second_result);
            }
        }
        StreamEdgeCase::OffsetOverflow {
            stream_index,
            offset,
            len,
        } => {
            if let Some(&id) = stream_ids.get(stream_index as usize % stream_ids.len().max(1)) {
                // Try to receive at an offset that would overflow
                let before_recv_remaining = table.connection_recv_remaining();
                let result = table.receive_stream_segment(id, offset, len, false);
                observe_receive_result(
                    "offset overflow receive segment",
                    table,
                    before_recv_remaining,
                    result,
                );
            }
        }
        StreamEdgeCase::FinalSizeViolation {
            stream_index,
            final_size,
            excess_data,
        } => {
            if let Some(&id) = stream_ids.get(stream_index as usize % stream_ids.len().max(1)) {
                let final_size_result = table.set_stream_final_size(id, final_size as u64);
                observe_table_result("final size violation setup", final_size_result);
                // Try to receive more data than the final size allows
                let before_recv_remaining = table.connection_recv_remaining();
                let receive_result =
                    table.receive_stream_segment(id, final_size as u64, excess_data as u64, false);
                observe_receive_result(
                    "final size violation receive",
                    table,
                    before_recv_remaining,
                    receive_result,
                );
            }
        }
        StreamEdgeCase::RangeMergingStress {
            stream_index,
            ranges,
        } => {
            if let Some(&id) = stream_ids.get(stream_index as usize % stream_ids.len().max(1)) {
                // Send overlapping and adjacent ranges to stress-test merging logic
                for (offset, len) in ranges.into_iter().take(50) {
                    // Limit to prevent timeouts
                    let before_recv_remaining = table.connection_recv_remaining();
                    let result = table.receive_stream_segment(id, offset as u64, len as u64, false);
                    observe_receive_result(
                        "range merging receive segment",
                        table,
                        before_recv_remaining,
                        result,
                    );
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
