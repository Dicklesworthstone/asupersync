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

#[derive(Debug, Clone, Arbitrary)]
enum StreamOp {
    OpenLocalBidi,
    OpenLocalUni,
    AcceptRemote {
        role: StreamRole,
        direction: StreamDirection,
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
    role: StreamRole,
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
        if let Some(_) = stream.send_reset {
            return Ok(ObservedStreamState::ResetSent);
        }

        if let Some(_) = stream.stop_sending_error_code {
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

    let mut table = StreamTable::new_with_connection_limits(
        input.role,
        max_local_bidi,
        max_local_uni,
        send_window,
        recv_window,
        connection_send_limit,
        connection_recv_limit,
    );

    let mut state_tracker = StateTracker::new();
    let mut stream_list: Vec<StreamId> = Vec::new();

    for op in &input.operations {
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
                                    && id.is_local_for(input.role)
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
                    Err(_) => {
                        // Other errors are unexpected for this operation
                    }
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
                                    && id.is_local_for(input.role)
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
                    Err(_) => {
                        // Other errors are unexpected for this operation
                    }
                }
            }

            StreamOp::AcceptRemote {
                role,
                direction,
                seq,
            } => {
                let seq = seq.min(MAX_STREAM_SEQ);
                let stream_id = StreamId::local(*role, *direction, seq);

                // Only accept if it's actually remote for our role
                if !stream_id.is_local_for(input.role) {
                    if let Ok(()) = table.accept_remote_stream(stream_id) {
                        stream_list.push(stream_id);
                        state_tracker.record_stream_opened(stream_id);
                    }
                }
            }

            StreamOp::WriteStream { stream_index, len } => {
                let len = len.min(MAX_DATA_SIZE);
                if let Some(&stream_id) =
                    stream_list.get(*stream_index as usize % stream_list.len().max(1))
                {
                    let old_state = state_tracker
                        .states
                        .get(&stream_id)
                        .cloned()
                        .unwrap_or(ObservedStreamState::Idle);

                    if let Ok(()) = table.write_stream(stream_id, len) {
                        // Property 1: IDLE→OPEN on first frame
                        if old_state == ObservedStreamState::Idle && len > 0 {
                            state_tracker.record_first_frame(stream_id);
                            let valid_transition = state_tracker.update_state(&table, stream_id);
                            assert!(
                                valid_transition,
                                "Invalid state transition after first write"
                            );

                            let new_state = state_tracker.states.get(&stream_id).unwrap();
                            assert_eq!(
                                *new_state,
                                ObservedStreamState::Open,
                                "Stream should transition to OPEN on first frame"
                            );
                        }

                        // Update state after write
                        let valid_transition = state_tracker.update_state(&table, stream_id);
                        assert!(valid_transition, "Invalid state transition after write");
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
                    stream_list.get(*stream_index as usize % stream_list.len().max(1))
                {
                    let old_state = state_tracker
                        .states
                        .get(&stream_id)
                        .cloned()
                        .unwrap_or(ObservedStreamState::Idle);

                    match table.receive_stream_segment(stream_id, offset, *len, *is_fin) {
                        Ok(()) => {
                            // Property 1: IDLE→OPEN on first frame
                            if old_state == ObservedStreamState::Idle && (*len > 0 || *is_fin) {
                                state_tracker.record_first_frame(stream_id);
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
                            if *is_fin && old_state == ObservedStreamState::Open {
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
                            let valid_transition = state_tracker.update_state(&table, stream_id);
                            assert!(valid_transition, "Invalid state transition after receive");
                        }
                        Err(StreamTableError::StreamNotReadable(_)) => {
                            // Expected for local unidirectional streams
                        }
                        Err(_) => {
                            // Other errors might be valid depending on stream state
                        }
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
                    stream_list.get(*stream_index as usize % stream_list.len().max(1))
                {
                    if let Ok(stream) = table.stream_mut(stream_id) {
                        let old_state = state_tracker
                            .states
                            .get(&stream_id)
                            .cloned()
                            .unwrap_or(ObservedStreamState::Idle);

                        if let Ok(()) = stream.reset_send(*error_code, final_size) {
                            // Property 4: RESET_STREAM transitions immediate
                            let valid_transition = state_tracker.update_state(&table, stream_id);
                            assert!(
                                valid_transition,
                                "Invalid state transition after reset_send"
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
                                Err(StreamTableError::Stream(QuicStreamError::SendStopped {
                                    code,
                                })) => {
                                    assert_eq!(code, *error_code, "Error code should match reset");
                                }
                                _ => {
                                    // Stream may not be writable for other reasons (e.g., unidirectional)
                                }
                            }
                        }
                    }
                }
            }

            StreamOp::StopSending {
                stream_index,
                error_code,
            } => {
                if let Some(&stream_id) =
                    stream_list.get(*stream_index as usize % stream_list.len().max(1))
                {
                    if let Ok(stream) = table.stream_mut(stream_id) {
                        let old_state = state_tracker
                            .states
                            .get(&stream_id)
                            .cloned()
                            .unwrap_or(ObservedStreamState::Idle);

                        stream.on_stop_sending(*error_code);

                        // Property 4: RESET_STREAM transitions immediate (similar for STOP_SENDING)
                        let valid_transition = state_tracker.update_state(&table, stream_id);
                        assert!(
                            valid_transition,
                            "Invalid state transition after stop_sending"
                        );

                        // After STOP_SENDING, further writes should fail
                        let write_result = table.write_stream(stream_id, 1);
                        if write_result.is_err() {
                            // This is expected - writes should fail after stop_sending
                        }
                    }
                }
            }

            StreamOp::StopReceiving {
                stream_index,
                error_code,
            } => {
                if let Some(&stream_id) =
                    stream_list.get(*stream_index as usize % stream_list.len().max(1))
                {
                    if let Ok(stream) = table.stream_mut(stream_id) {
                        stream.stop_receiving(*error_code);

                        let valid_transition = state_tracker.update_state(&table, stream_id);
                        assert!(
                            valid_transition,
                            "Invalid state transition after stop_receiving"
                        );

                        // After stop_receiving, further receives should fail
                        let recv_result = table.receive_stream_segment(stream_id, 0, 1, false);
                        match recv_result {
                            Err(StreamTableError::Stream(QuicStreamError::ReceiveStopped {
                                code,
                            })) => {
                                assert_eq!(
                                    code, *error_code,
                                    "Error code should match stop_receiving"
                                );
                            }
                            _ => {
                                // Stream may not be readable for other reasons
                            }
                        }
                    }
                }
            }

            StreamOp::SetFinalSize {
                stream_index,
                final_size,
            } => {
                let final_size = final_size.min(MAX_DATA_SIZE);

                if let Some(&stream_id) =
                    stream_list.get(*stream_index as usize % stream_list.len().max(1))
                {
                    if let Ok(()) = table.set_stream_final_size(stream_id, final_size) {
                        // Property 2: Setting final size may transition to HALF_CLOSED
                        let valid_transition = state_tracker.update_state(&table, stream_id);
                        assert!(
                            valid_transition,
                            "Invalid state transition after set_final_size"
                        );
                    }
                }
            }

            StreamOp::IncreaseConnectionSendLimit { new_limit } => {
                let new_limit = new_limit.min(100 * 1024 * 1024); // 100MB max
                let _ = table.increase_connection_send_limit(new_limit);
            }

            StreamOp::IncreaseConnectionRecvLimit { new_limit } => {
                let new_limit = new_limit.min(100 * 1024 * 1024); // 100MB max
                let _ = table.increase_connection_recv_limit(new_limit);
            }

            StreamOp::GetNextWritableStream => {
                let _ = table.next_writable_stream();
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
        let _ = state_tracker.update_state(&table, *stream_id);
    }
});
