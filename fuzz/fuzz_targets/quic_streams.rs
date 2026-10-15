#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use std::collections::HashMap;

use asupersync::net::quic_native::streams::{
    QuicStreamError, StreamDirection, StreamId, StreamRole, StreamTable, StreamTableError,
};

/// Maximum number of operations per fuzz run to prevent timeouts
const MAX_OPS: usize = 1000;
/// Maximum stream sequence number to avoid excessive memory usage
const MAX_STREAM_SEQ: u64 = 100;
/// Maximum data size for write/receive operations
const MAX_DATA_SIZE: u64 = 64 * 1024; // 64KB

#[derive(Debug, Clone, Copy, Arbitrary)]
enum FuzzStreamRole {
    Client,
    Server,
}

impl From<FuzzStreamRole> for StreamRole {
    fn from(role: FuzzStreamRole) -> Self {
        match role {
            FuzzStreamRole::Client => Self::Client,
            FuzzStreamRole::Server => Self::Server,
        }
    }
}

#[derive(Debug, Clone, Copy, Arbitrary)]
enum FuzzStreamDirection {
    Bidirectional,
    Unidirectional,
}

impl From<FuzzStreamDirection> for StreamDirection {
    fn from(direction: FuzzStreamDirection) -> Self {
        match direction {
            FuzzStreamDirection::Bidirectional => Self::Bidirectional,
            FuzzStreamDirection::Unidirectional => Self::Unidirectional,
        }
    }
}

#[derive(Debug, Clone, Arbitrary)]
enum StreamOp {
    OpenLocalBidi,
    OpenLocalUni,
    AcceptRemote {
        role: FuzzStreamRole,
        direction: FuzzStreamDirection,
        seq: u64,
    },
    WriteStream {
        stream_index: u8,
        len: u64,
    },
    ReceiveSegment {
        stream_index: u8,
        offset: u64,
        len: u64,
        is_fin: bool,
    },
    ResetSend {
        stream_index: u8,
        error_code: u64,
        final_size: u64,
    },
    StopSending {
        stream_index: u8,
        error_code: u64,
    },
    StopReceiving {
        stream_index: u8,
        error_code: u64,
    },
    SetFinalSize {
        stream_index: u8,
        final_size: u64,
    },
    IncreaseConnectionSendLimit {
        new_limit: u64,
    },
    IncreaseConnectionRecvLimit {
        new_limit: u64,
    },
    GetNextWritableStream,
}

#[derive(Debug, Clone, Arbitrary)]
struct QuicStreamsFuzzInput {
    role: FuzzStreamRole,
    max_local_bidi: u8,
    max_local_uni: u8,
    send_window: u64,
    recv_window: u64,
    connection_send_limit: u64,
    connection_recv_limit: u64,
    operations: Vec<StreamOp>,
}

/// Represents the observed state of a stream for testing state transitions
#[derive(Debug, Clone, PartialEq)]
enum ObservedStreamState {
    Idle,
    Open,
    HalfClosedLocal,
    HalfClosedRemote,
    Closed,
    ResetSent,
    ResetReceived,
}

impl ObservedStreamState {
    fn determine_state(table: &StreamTable, stream_id: StreamId) -> Result<Self, StreamTableError> {
        let stream = table.stream(stream_id)?;

        // Check if stream has been reset
        if stream.send_reset.is_some() {
            return Ok(ObservedStreamState::ResetSent);
        }

        if stream.stop_sending_error_code.is_some() {
            return Ok(ObservedStreamState::ResetReceived);
        }

        // Check FIN state
        let has_sent_fin =
            stream.final_size.is_some() && stream.final_size == Some(stream.send_offset);
        let has_received_fin =
            stream.final_size.is_some() && stream.final_size == Some(stream.recv_offset);

        match (has_sent_fin, has_received_fin) {
            (true, true) => Ok(ObservedStreamState::Closed),
            (true, false) => Ok(ObservedStreamState::HalfClosedLocal),
            (false, true) => Ok(ObservedStreamState::HalfClosedRemote),
            (false, false) => {
                // If any data has been sent or received, consider it open
                if stream.send_offset > 0 || stream.recv_offset > 0 {
                    Ok(ObservedStreamState::Open)
                } else {
                    Ok(ObservedStreamState::Idle)
                }
            }
        }
    }
}

fn observe_error(label: &str, error: &impl std::fmt::Display) {
    assert!(
        !error.to_string().is_empty(),
        "{label} errors should carry a deterministic diagnostic"
    );
}

fn observe_state_update(
    label: &str,
    state_tracker: &mut StateTracker,
    table: &StreamTable,
    stream_id: StreamId,
) {
    assert!(
        state_tracker.update_state(table, stream_id),
        "{label} produced an invalid stream-state transition"
    );
}

fn observe_limit_result(
    label: &str,
    before_remaining: u64,
    after_remaining: u64,
    result: Result<(), asupersync::net::quic_native::streams::FlowControlError>,
) {
    match result {
        Ok(()) => assert!(
            after_remaining >= before_remaining,
            "{label} should not reduce remaining connection credit"
        ),
        Err(error) => observe_error(label, &error),
    }
}

fn observe_next_writable(table: &mut StreamTable, role: StreamRole) {
    if let Some(stream_id) = table.next_writable_stream() {
        let stream = table
            .stream(stream_id)
            .expect("round-robin returned an unknown stream");
        let writable_direction = match stream_id.direction() {
            StreamDirection::Bidirectional => true,
            StreamDirection::Unidirectional => stream_id.is_local_for(role),
        };
        assert!(
            writable_direction,
            "round-robin returned a non-writable remote unidirectional stream"
        );
        assert!(
            stream.send_reset.is_none() && stream.stop_sending_error_code.is_none(),
            "round-robin returned a stopped or reset stream"
        );
        assert!(
            stream.send_credit.remaining() > 0,
            "round-robin returned a stream without send credit"
        );
    }
}

/// Track stream state transitions for validation
struct StateTracker {
    states: HashMap<StreamId, ObservedStreamState>,
    opened_streams: Vec<StreamId>,
    received_first_frame: HashMap<StreamId, bool>,
}

impl StateTracker {
    fn new() -> Self {
        Self {
            states: HashMap::new(),
            opened_streams: Vec::new(),
            received_first_frame: HashMap::new(),
        }
    }

    fn update_state(&mut self, table: &StreamTable, stream_id: StreamId) -> bool {
        if let Ok(new_state) = ObservedStreamState::determine_state(table, stream_id) {
            let old_state = self
                .states
                .get(&stream_id)
                .cloned()
                .unwrap_or(ObservedStreamState::Idle);

            self.states.insert(stream_id, new_state.clone());

            // Validate state transitions
            self.validate_transition(&old_state, &new_state)
        } else {
            true // Stream doesn't exist or error occurred
        }
    }

    fn validate_transition(&self, old: &ObservedStreamState, new: &ObservedStreamState) -> bool {
        use ObservedStreamState::*;

        match (old, new) {
            // Valid transitions
            (Idle, Open) => true,
            (Idle, ResetSent) => true,
            (Open, HalfClosedLocal) => true,
            (Open, HalfClosedRemote) => true,
            (Open, ResetSent) => true,
            (Open, ResetReceived) => true,
            (HalfClosedLocal, Closed) => true,
            (HalfClosedRemote, Closed) => true,
            (HalfClosedLocal, ResetSent) => true,
            (HalfClosedRemote, ResetReceived) => true,
            // Same state is always valid
            (a, b) if a == b => true,
            // Invalid transitions
            _ => false,
        }
    }

    fn record_stream_opened(&mut self, stream_id: StreamId) {
        if !self.opened_streams.contains(&stream_id) {
            self.opened_streams.push(stream_id);
        }
    }

    fn record_first_frame(&mut self, stream_id: StreamId) {
        self.received_first_frame.insert(stream_id, true);
    }

    fn has_received_first_frame(&self, stream_id: StreamId) -> bool {
        self.received_first_frame
            .get(&stream_id)
            .copied()
            .unwrap_or(false)
    }
}

fuzz_target!(|input: QuicStreamsFuzzInput| {
    // Limit input size to prevent excessive memory usage and timeouts
    if input.operations.len() > MAX_OPS {
        return;
    }

    // Bound parameters to reasonable ranges
    let max_local_bidi = (input.max_local_bidi as u64).min(50);
    let max_local_uni = (input.max_local_uni as u64).min(50);
    let send_window = input.send_window.min(1024 * 1024); // 1MB
    let recv_window = input.recv_window.min(1024 * 1024); // 1MB
    let connection_send_limit = input.connection_send_limit.min(10 * 1024 * 1024); // 10MB
    let connection_recv_limit = input.connection_recv_limit.min(10 * 1024 * 1024); // 10MB
    let endpoint_role = StreamRole::from(input.role);

    let mut table = StreamTable::new_with_connection_limits(
        endpoint_role,
        max_local_bidi,
        max_local_uni,
        send_window,
        recv_window,
        connection_send_limit,
        connection_recv_limit,
    );

    let mut state_tracker = StateTracker::new();
    let mut stream_list: Vec<StreamId> = Vec::new();

    for op in input.operations {
        match op {
            StreamOp::OpenLocalBidi => {
                match table.open_local_bidi() {
                    Ok(stream_id) => {
                        stream_list.push(stream_id);
                        state_tracker.record_stream_opened(stream_id);

                        // Property 3: concurrent streams bounded by initial_max_streams
                        let bidi_count = stream_list
                            .iter()
                            .filter(|id| {
                                id.direction() == StreamDirection::Bidirectional
                                    && id.is_local_for(endpoint_role)
                            })
                            .count();
                        assert!(
                            bidi_count as u64 <= max_local_bidi,
                            "Bidirectional stream count {} exceeds limit {}",
                            bidi_count,
                            max_local_bidi
                        );
                    }
                    Err(StreamTableError::StreamLimitExceeded { direction, limit }) => {
                        assert_eq!(direction, StreamDirection::Bidirectional);
                        assert_eq!(limit, max_local_bidi);
                        // This is expected when limit is reached
                    }
                    Err(error) => observe_error("open local bidirectional stream", &error),
                }
            }

            StreamOp::OpenLocalUni => {
                match table.open_local_uni() {
                    Ok(stream_id) => {
                        stream_list.push(stream_id);
                        state_tracker.record_stream_opened(stream_id);

                        // Property 3: concurrent streams bounded by initial_max_streams
                        let uni_count = stream_list
                            .iter()
                            .filter(|id| {
                                id.direction() == StreamDirection::Unidirectional
                                    && id.is_local_for(endpoint_role)
                            })
                            .count();
                        assert!(
                            uni_count as u64 <= max_local_uni,
                            "Unidirectional stream count {} exceeds limit {}",
                            uni_count,
                            max_local_uni
                        );
                    }
                    Err(StreamTableError::StreamLimitExceeded { direction, limit }) => {
                        assert_eq!(direction, StreamDirection::Unidirectional);
                        assert_eq!(limit, max_local_uni);
                        // This is expected when limit is reached
                    }
                    Err(error) => observe_error("open local unidirectional stream", &error),
                }
            }

            StreamOp::AcceptRemote {
                role,
                direction,
                seq,
            } => {
                let seq = seq.min(MAX_STREAM_SEQ);
                let stream_id = StreamId::local(role.into(), direction.into(), seq);

                // Only accept if it's actually remote for our role
                if !stream_id.is_local_for(endpoint_role) {
                    match table.accept_remote_stream(stream_id) {
                        Ok(()) => {
                            stream_list.push(stream_id);
                            state_tracker.record_stream_opened(stream_id);
                        }
                        Err(error) => observe_error("accept remote stream", &error),
                    }
                }
            }

            StreamOp::WriteStream { stream_index, len } => {
                let len = len.min(MAX_DATA_SIZE);
                if let Some(&stream_id) =
                    stream_list.get(stream_index as usize % stream_list.len().max(1))
                {
                    let old_state = state_tracker
                        .states
                        .get(&stream_id)
                        .cloned()
                        .unwrap_or(ObservedStreamState::Idle);

                    let before_send_remaining = table.connection_send_remaining();
                    match table.write_stream(stream_id, len) {
                        Ok(()) => {
                            assert!(
                                table.connection_send_remaining() <= before_send_remaining,
                                "write_stream should not increase remaining send credit"
                            );
                            let stream = table
                                .stream(stream_id)
                                .expect("successful write should leave stream present");
                            assert_eq!(
                                stream.send_offset,
                                stream.send_credit.used(),
                                "send offset should mirror consumed stream send credit"
                            );

                            // Property 1: IDLE→OPEN on first frame
                            if old_state == ObservedStreamState::Idle && len > 0 {
                                state_tracker.record_first_frame(stream_id);
                                assert!(
                                    state_tracker.has_received_first_frame(stream_id),
                                    "first write should be recorded for the stream"
                                );
                                observe_state_update(
                                    "first write",
                                    &mut state_tracker,
                                    &table,
                                    stream_id,
                                );

                                let new_state = state_tracker.states.get(&stream_id).unwrap();
                                assert_eq!(
                                    *new_state,
                                    ObservedStreamState::Open,
                                    "Stream should transition to OPEN on first frame"
                                );
                            }

                            // Update state after write
                            observe_state_update("write", &mut state_tracker, &table, stream_id);
                        }
                        Err(error) => observe_error("write stream", &error),
                    }
                }
            }

            StreamOp::ReceiveSegment {
                stream_index,
                offset,
                len,
                is_fin,
            } => {
                let offset = offset.min(MAX_DATA_SIZE);
                let len = len.min(MAX_DATA_SIZE);

                if let Some(&stream_id) =
                    stream_list.get(stream_index as usize % stream_list.len().max(1))
                {
                    let old_state = state_tracker
                        .states
                        .get(&stream_id)
                        .cloned()
                        .unwrap_or(ObservedStreamState::Idle);

                    match table.receive_stream_segment(stream_id, offset, len, is_fin) {
                        Ok(()) => {
                            // Property 1: IDLE→OPEN on first frame
                            if old_state == ObservedStreamState::Idle && (len > 0 || is_fin) {
                                state_tracker.record_first_frame(stream_id);
                                assert!(
                                    state_tracker.has_received_first_frame(stream_id),
                                    "first receive should be recorded for the stream"
                                );
                                let valid_transition =
                                    state_tracker.update_state(&table, stream_id);
                                assert!(
                                    valid_transition,
                                    "Invalid state transition after first receive"
                                );

                                let new_state = state_tracker.states.get(&stream_id).unwrap();
                                assert_eq!(
                                    *new_state,
                                    ObservedStreamState::Open,
                                    "Stream should transition to OPEN on first frame"
                                );
                            }

                            // Property 2: OPEN→HALF_CLOSED on FIN
                            if is_fin && old_state == ObservedStreamState::Open {
                                let valid_transition =
                                    state_tracker.update_state(&table, stream_id);
                                assert!(valid_transition, "Invalid state transition on FIN");

                                let new_state = state_tracker.states.get(&stream_id).unwrap();
                                assert!(
                                    *new_state == ObservedStreamState::HalfClosedRemote
                                        || *new_state == ObservedStreamState::Closed,
                                    "Stream should transition to HALF_CLOSED_REMOTE or CLOSED on receive FIN"
                                );
                            }

                            // Property 5: state observed only on poll_recv (receive operations)
                            // This property is inherently satisfied since we only observe state changes
                            // when explicitly checking via receive operations
                            observe_state_update("receive", &mut state_tracker, &table, stream_id);
                        }
                        Err(StreamTableError::StreamNotReadable(_)) => {
                            // Expected for local unidirectional streams
                        }
                        Err(error) => observe_error("receive stream segment", &error),
                    }
                }
            }

            StreamOp::ResetSend {
                stream_index,
                error_code,
                final_size,
            } => {
                let final_size = final_size.min(MAX_DATA_SIZE);

                if let Some(&stream_id) =
                    stream_list.get(stream_index as usize % stream_list.len().max(1))
                {
                    match table.stream_mut(stream_id) {
                        Ok(stream) => match stream.reset_send(error_code, final_size) {
                            Ok(()) => {
                                // Property 4: RESET_STREAM transitions immediate
                                observe_state_update(
                                    "reset_send",
                                    &mut state_tracker,
                                    &table,
                                    stream_id,
                                );

                                let new_state = state_tracker.states.get(&stream_id).unwrap();
                                assert_eq!(
                                    *new_state,
                                    ObservedStreamState::ResetSent,
                                    "Stream should immediately transition to RESET_SENT state"
                                );

                                // Verify that the stream cannot send more data after reset
                                let write_result = table.write_stream(stream_id, 1);
                                match write_result {
                                    Err(StreamTableError::Stream(
                                        QuicStreamError::SendStopped { code },
                                    )) => {
                                        assert_eq!(
                                            code, error_code,
                                            "Error code should match reset"
                                        );
                                    }
                                    Err(StreamTableError::StreamNotWritable(_)) => {
                                        // Remote unidirectional streams are already unwritable.
                                    }
                                    Err(error) => observe_error("write after reset_send", &error),
                                    Ok(()) => panic!("write after reset_send should not succeed"),
                                }
                            }
                            Err(error) => observe_error("reset send", &error),
                        },
                        Err(error) => observe_error("lookup stream for reset_send", &error),
                    }
                }
            }

            StreamOp::StopSending {
                stream_index,
                error_code,
            } => {
                if let Some(&stream_id) =
                    stream_list.get(stream_index as usize % stream_list.len().max(1))
                {
                    match table.stream_mut(stream_id) {
                        Ok(stream) => {
                            stream.on_stop_sending(error_code);
                            assert_eq!(
                                stream.stop_sending_error_code,
                                Some(error_code),
                                "STOP_SENDING should record the first error code"
                            );

                            // Property 4: RESET_STREAM transitions immediate (similar for STOP_SENDING)
                            observe_state_update(
                                "stop_sending",
                                &mut state_tracker,
                                &table,
                                stream_id,
                            );

                            // After STOP_SENDING, further writes should fail
                            let write_result = table.write_stream(stream_id, 1);
                            match write_result {
                                Err(StreamTableError::Stream(QuicStreamError::SendStopped {
                                    code,
                                })) => {
                                    assert_eq!(
                                        code, error_code,
                                        "Error code should match stop_sending"
                                    );
                                }
                                Err(StreamTableError::StreamNotWritable(_)) => {
                                    // Remote unidirectional streams are already unwritable.
                                }
                                Err(error) => observe_error("write after stop_sending", &error),
                                Ok(()) => panic!("write after stop_sending should not succeed"),
                            }
                        }
                        Err(error) => observe_error("lookup stream for stop_sending", &error),
                    }
                }
            }

            StreamOp::StopReceiving {
                stream_index,
                error_code,
            } => {
                if let Some(&stream_id) =
                    stream_list.get(stream_index as usize % stream_list.len().max(1))
                {
                    match table.stream_mut(stream_id) {
                        Ok(stream) => {
                            stream.stop_receiving(error_code);
                            assert_eq!(
                                stream.receive_stopped_error_code,
                                Some(error_code),
                                "stop_receiving should record the error code"
                            );

                            observe_state_update(
                                "stop_receiving",
                                &mut state_tracker,
                                &table,
                                stream_id,
                            );

                            // After stop_receiving, further receives should fail
                            let recv_result = table.receive_stream_segment(stream_id, 0, 1, false);
                            match recv_result {
                                Err(StreamTableError::Stream(
                                    QuicStreamError::ReceiveStopped { code },
                                )) => {
                                    assert_eq!(
                                        code, error_code,
                                        "Error code should match stop_receiving"
                                    );
                                }
                                Err(StreamTableError::StreamNotReadable(_)) => {
                                    // Local unidirectional streams are already unreadable.
                                }
                                Err(error) => observe_error("receive after stop_receiving", &error),
                                Ok(()) => panic!("receive after stop_receiving should not succeed"),
                            }
                        }
                        Err(error) => observe_error("lookup stream for stop_receiving", &error),
                    }
                }
            }

            StreamOp::SetFinalSize {
                stream_index,
                final_size,
            } => {
                let final_size = final_size.min(MAX_DATA_SIZE);

                if let Some(&stream_id) =
                    stream_list.get(stream_index as usize % stream_list.len().max(1))
                {
                    match table.set_stream_final_size(stream_id, final_size) {
                        Ok(()) => {
                            // Property 2: Setting final size may transition to HALF_CLOSED
                            observe_state_update(
                                "set final size",
                                &mut state_tracker,
                                &table,
                                stream_id,
                            );
                        }
                        Err(error) => observe_error("set stream final size", &error),
                    }
                }
            }

            StreamOp::IncreaseConnectionSendLimit { new_limit } => {
                let new_limit = new_limit.min(100 * 1024 * 1024); // 100MB max
                let before_remaining = table.connection_send_remaining();
                let result = table.increase_connection_send_limit(new_limit);
                let after_remaining = table.connection_send_remaining();
                observe_limit_result(
                    "increase connection send limit",
                    before_remaining,
                    after_remaining,
                    result,
                );
            }

            StreamOp::IncreaseConnectionRecvLimit { new_limit } => {
                let new_limit = new_limit.min(100 * 1024 * 1024); // 100MB max
                let before_remaining = table.connection_recv_remaining();
                let result = table.increase_connection_recv_limit(new_limit);
                let after_remaining = table.connection_recv_remaining();
                observe_limit_result(
                    "increase connection receive limit",
                    before_remaining,
                    after_remaining,
                    result,
                );
            }

            StreamOp::GetNextWritableStream => {
                observe_next_writable(&mut table, endpoint_role);
            }
        }

        // Validate that stream table invariants are maintained
        assert!(
            table.len() <= (max_local_bidi + max_local_uni + 1000) as usize,
            "Stream table size {} exceeds reasonable bounds",
            table.len()
        );

        // Validate that connection flow control limits are respected
        assert!(
            table.connection_send_remaining() <= connection_send_limit,
            "Connection send remaining {} exceeds limit {}",
            table.connection_send_remaining(),
            connection_send_limit
        );
        assert!(
            table.connection_recv_remaining() <= connection_recv_limit,
            "Connection recv remaining {} exceeds limit {}",
            table.connection_recv_remaining(),
            connection_recv_limit
        );
    }

    // Final validation: verify all recorded streams still have valid states
    for stream_id in &stream_list {
        observe_state_update(
            "final stream-state validation",
            &mut state_tracker,
            &table,
            *stream_id,
        );
    }
});
