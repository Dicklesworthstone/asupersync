//! Fuzz target for QUIC STREAM frame parsing and processing
//!
//! Feeds malformed QUIC STREAM frames to the stream handler and validates
//! protocol invariants hold under adversarial input:
//!
//! 1. Stream ID bit encoding (direction/initiator) correctly decoded
//! 2. Varint offsets do not overflow u64
//! 3. FIN flag operations are idempotent
//! 4. Stream types (unidirectional/bidirectional) are honored
//! 5. MAX_STREAM_DATA flow control is enforced
//! 6. RESET_STREAM transitions are valid

#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use asupersync::net::quic_core::{QUIC_VARINT_MAX, QuicCoreError, decode_varint, encode_varint};
use asupersync::net::quic_native::streams::{
    FlowControlError, QuicStreamError, StreamDirection, StreamId, StreamRole, StreamTable,
    StreamTableError,
};
use libfuzzer_sys::fuzz_target;
use std::collections::HashMap;

/// QUIC STREAM frame types (RFC 9000 Section 19.8)
const STREAM_FRAME_TYPE_BASE: u8 = 0x08; // 0x08-0x0f
const STREAM_FRAME_FIN_BIT: u8 = 0x01;
const STREAM_FRAME_LEN_BIT: u8 = 0x02;
const STREAM_FRAME_OFF_BIT: u8 = 0x04;

/// RESET_STREAM frame type (RFC 9000 Section 19.4)
const RESET_STREAM_FRAME_TYPE: u8 = 0x04;

/// MAX_STREAM_DATA frame type (RFC 9000 Section 19.10)
const MAX_STREAM_DATA_FRAME_TYPE: u8 = 0x11;

/// STOP_SENDING frame type (RFC 9000 Section 19.5)
const STOP_SENDING_FRAME_TYPE: u8 = 0x05;

/// Maximum reasonable stream window for fuzzing (1GB)
const MAX_FUZZ_WINDOW: u64 = 1_000_000_000;

/// Maximum reasonable payload size for fuzzing (1MB)
const MAX_FUZZ_PAYLOAD: usize = 1_000_000;

#[derive(Debug, Clone, Arbitrary)]
enum QuicStreamOperation {
    SendStreamFrame {
        stream_id: u64,
        offset: u64,
        payload: Vec<u8>,
        fin: bool,
        include_length: bool,
        include_offset: bool,
    },
    SendMalformedStreamFrame {
        raw_bytes: Vec<u8>,
    },
    SendResetStreamFrame {
        stream_id: u64,
        error_code: u64,
        final_size: u64,
    },
    SendMaxStreamDataFrame {
        stream_id: u64,
        max_data: u64,
    },
    SendStopSendingFrame {
        stream_id: u64,
        error_code: u64,
    },
    TestStreamIdEncoding {
        role: bool,      // true = client, false = server
        direction: bool, // true = bidi, false = uni
        sequence: u64,
    },
    TestVarintOverflow {
        base_offset: u64,
        length: u64,
    },
    TestFinIdempotency {
        stream_id: u64,
        payload1: Vec<u8>,
        payload2: Vec<u8>,
        final_size: u64,
    },
    TestFlowControlEnforcement {
        stream_id: u64,
        initial_window: u64,
        data_sequence: Vec<u64>,
    },
    TestResetTransitions {
        stream_id: u64,
        write_data_len: u64,
        reset_final_size: u64,
        error_code: u64,
        second_reset_final_size: Option<u64>,
    },
}

/// Shadow model for QUIC stream protocol validation
#[derive(Debug)]
struct QuicStreamShadowModel {
    role: StreamRole,
    stream_tables: HashMap<u8, StreamTable>, // Multiple tables for different test scenarios
    expected_stream_states: HashMap<u64, ExpectedStreamState>,
    connection_flow_limits: (u64, u64), // (send, recv)
    varint_overflow_detected: bool,
    fin_idempotency_violations: Vec<String>,
    flow_control_violations: Vec<String>,
    reset_transition_violations: Vec<String>,
    stream_id_encoding_violations: Vec<String>,
}

#[derive(Debug, Clone)]
struct ExpectedStreamState {
    id: StreamId,
    direction: StreamDirection,
    is_local: bool,
    send_offset: u64,
    recv_offset: u64,
    final_size: Option<u64>,
    is_reset: bool,
    reset_error_code: Option<u64>,
    stop_sending_error_code: Option<u64>,
}

fn observe_error(label: &str, error: &impl std::fmt::Display) {
    assert!(
        !error.to_string().is_empty(),
        "{label} errors should carry a deterministic diagnostic"
    );
}

fn observe_decode_result(
    label: &str,
    result: Result<(u64, u64, usize, bool), QuicCoreError>,
) -> Option<(u64, u64, usize, bool)> {
    match result {
        Ok((stream_id, offset, payload_len, fin)) => {
            assert!(
                stream_id <= QUIC_VARINT_MAX,
                "{label} decoded a stream ID outside QUIC varint bounds"
            );
            assert!(
                offset <= QUIC_VARINT_MAX,
                "{label} decoded an offset outside QUIC varint bounds"
            );
            Some((stream_id, offset, payload_len, fin))
        }
        Err(error) => {
            observe_error(label, &error);
            None
        }
    }
}

fn observe_decode_probe(label: &str, result: Result<(u64, u64, usize, bool), QuicCoreError>) {
    if let Some((stream_id, offset, payload_len, fin)) = observe_decode_result(label, result) {
        assert!(
            offset.checked_add(payload_len as u64).is_some(),
            "{label} decoded payload length should not overflow offset arithmetic"
        );
        if fin {
            assert!(
                stream_id <= QUIC_VARINT_MAX,
                "{label} FIN frame stream ID should remain within varint bounds"
            );
        }
    }
}

fn observe_accept_remote_result(
    label: &str,
    table: &StreamTable,
    before_len: usize,
    stream_id: StreamId,
    result: Result<(), StreamTableError>,
) -> bool {
    match result {
        Ok(()) => {
            assert_eq!(
                table.len(),
                before_len + 1,
                "{label} should insert exactly one remote stream"
            );
            assert!(
                table.stream(stream_id).is_ok(),
                "{label} inserted stream should be readable from the table"
            );
            true
        }
        Err(error) => {
            observe_error(label, &error);
            false
        }
    }
}

fn ensure_remote_stream(label: &str, table: &mut StreamTable, stream_id: StreamId) -> bool {
    if table.stream(stream_id).is_ok() {
        return true;
    }

    let before_len = table.len();
    let result = table.accept_remote_stream(stream_id);
    observe_accept_remote_result(label, table, before_len, stream_id, result)
}

fn observe_receive_result(
    label: &str,
    table: &StreamTable,
    stream_id: StreamId,
    before_recv_remaining: u64,
    result: Result<(), StreamTableError>,
) {
    match result {
        Ok(()) => {
            assert!(
                table.connection_recv_remaining() <= before_recv_remaining,
                "{label} should not increase receive credit while receiving"
            );
            let stream = table
                .stream(stream_id)
                .expect("successful receive should leave the stream present");
            assert!(
                stream.recv_offset <= stream.recv_credit.used(),
                "{label} contiguous receive offset should not exceed consumed receive credit"
            );
            if let Some(final_size) = stream.final_size {
                assert!(
                    final_size >= stream.recv_credit.used(),
                    "{label} final size should cover observed receive credit"
                );
            }
        }
        Err(error) => observe_error(label, &error),
    }
}

fn observe_write_result(
    label: &str,
    table: &StreamTable,
    stream_id: StreamId,
    before_send_remaining: u64,
    result: Result<(), StreamTableError>,
) {
    match result {
        Ok(()) => {
            assert!(
                table.connection_send_remaining() <= before_send_remaining,
                "{label} should not increase send credit while writing"
            );
            let stream = table
                .stream(stream_id)
                .expect("successful write should leave the stream present");
            assert_eq!(
                stream.send_offset,
                stream.send_credit.used(),
                "{label} send offset should mirror consumed send credit"
            );
        }
        Err(error) => observe_error(label, &error),
    }
}

fn observe_stream_reset_result(
    label: &str,
    stream_id: StreamId,
    stream: &asupersync::net::quic_native::streams::QuicStream,
    result: Result<(), QuicStreamError>,
) {
    match result {
        Ok(()) => {
            assert!(
                stream.send_reset.is_some(),
                "{label} should record reset state for stream {}",
                stream_id.0
            );
            let (_, final_size) = stream
                .send_reset
                .expect("reset state was checked immediately above");
            assert!(
                final_size >= stream.send_offset,
                "{label} final size should cover bytes already sent"
            );
        }
        Err(error) => observe_error(label, &error),
    }
}

impl QuicStreamShadowModel {
    fn new() -> Self {
        let role = StreamRole::Client;
        let mut stream_tables = HashMap::new();

        // Create multiple stream tables for different test scenarios
        for i in 0..4 {
            let table = StreamTable::new_with_connection_limits(
                role,
                100,                 // max_local_bidi
                100,                 // max_local_uni
                MAX_FUZZ_WINDOW,     // send_window
                MAX_FUZZ_WINDOW,     // recv_window
                MAX_FUZZ_WINDOW * 2, // connection_send_limit
                MAX_FUZZ_WINDOW * 2, // connection_recv_limit
            );
            stream_tables.insert(i, table);
        }

        Self {
            role,
            stream_tables,
            expected_stream_states: HashMap::new(),
            connection_flow_limits: (MAX_FUZZ_WINDOW * 2, MAX_FUZZ_WINDOW * 2),
            varint_overflow_detected: false,
            fin_idempotency_violations: Vec::new(),
            flow_control_violations: Vec::new(),
            reset_transition_violations: Vec::new(),
            stream_id_encoding_violations: Vec::new(),
        }
    }

    fn validate_stream_id_encoding(&mut self, role_bit: bool, direction_bit: bool, sequence: u64) {
        let role = if role_bit {
            StreamRole::Client
        } else {
            StreamRole::Server
        };
        let direction = if direction_bit {
            StreamDirection::Bidirectional
        } else {
            StreamDirection::Unidirectional
        };

        if sequence >= (1u64 << 62) {
            self.stream_id_encoding_violations
                .push(format!("Stream sequence {} exceeds 62-bit limit", sequence));
            return;
        }

        let stream_id = StreamId::local(role, direction, sequence);

        // Verify bit encoding: low 2 bits encode type, upper 62 bits encode sequence
        let expected_low_bits = (direction_bit as u64) << 1 | (role_bit as u64);
        let actual_low_bits = stream_id.0 & 0x3;

        if actual_low_bits != expected_low_bits {
            self.stream_id_encoding_violations.push(format!(
                "Stream ID encoding mismatch: expected low bits {}, got {}",
                expected_low_bits, actual_low_bits
            ));
        }

        // Verify direction extraction
        let extracted_direction = stream_id.direction();
        if extracted_direction != direction {
            self.stream_id_encoding_violations.push(format!(
                "Direction extraction failed: expected {:?}, got {:?}",
                direction, extracted_direction
            ));
        }

        // Verify locality check
        let is_local_for_role = stream_id.is_local_for(role);
        if !is_local_for_role {
            self.stream_id_encoding_violations.push(format!(
                "Local stream ID not recognized as local for role {:?}",
                role
            ));
        }

        // Verify sequence extraction
        let extracted_sequence = stream_id.0 >> 2;
        if extracted_sequence != sequence {
            self.stream_id_encoding_violations.push(format!(
                "Sequence extraction failed: expected {}, got {}",
                sequence, extracted_sequence
            ));
        }
    }

    fn validate_varint_overflow(&mut self, base_offset: u64, length: u64) -> bool {
        if base_offset > QUIC_VARINT_MAX {
            self.varint_overflow_detected = true;
            return false;
        }
        if length > QUIC_VARINT_MAX {
            self.varint_overflow_detected = true;
            return false;
        }

        match base_offset.checked_add(length) {
            Some(end) => {
                if end > QUIC_VARINT_MAX {
                    self.varint_overflow_detected = true;
                    false
                } else {
                    true
                }
            }
            None => {
                self.varint_overflow_detected = true;
                false
            }
        }
    }

    fn process_stream_frame(
        &mut self,
        stream_id: u64,
        offset: u64,
        payload: &[u8],
        fin: bool,
        table_id: u8,
    ) {
        if !self.validate_varint_overflow(offset, payload.len() as u64) {
            return; // Overflow detected, stop processing
        }

        let stream_id = StreamId(stream_id);
        let table = match self.stream_tables.get_mut(&table_id) {
            Some(table) => table,
            None => return,
        };

        ensure_remote_stream("accept remote stream for STREAM frame", table, stream_id);

        let before_recv_remaining = table.connection_recv_remaining();
        match table.receive_stream_segment(stream_id, offset, payload.len() as u64, fin) {
            Ok(()) => {
                observe_receive_result(
                    "receive STREAM frame segment",
                    table,
                    stream_id,
                    before_recv_remaining,
                    Ok(()),
                );
                // Update expected state
                let state = self
                    .expected_stream_states
                    .entry(stream_id.0)
                    .or_insert_with(|| ExpectedStreamState {
                        id: stream_id,
                        direction: stream_id.direction(),
                        is_local: stream_id.is_local_for(self.role),
                        send_offset: 0,
                        recv_offset: 0,
                        final_size: None,
                        is_reset: false,
                        reset_error_code: None,
                        stop_sending_error_code: None,
                    });
                state.recv_offset = state.recv_offset.max(offset + payload.len() as u64);

                if fin {
                    let end_offset = offset + payload.len() as u64;
                    if let Some(existing_final_size) = state.final_size {
                        if existing_final_size != end_offset {
                            self.fin_idempotency_violations.push(
                                format!(
                                    "FIN flag not idempotent: stream {}, previous final size {}, new final size {}",
                                    stream_id.0, existing_final_size, end_offset
                                )
                            );
                        }
                    } else {
                        state.final_size = Some(end_offset);
                    }
                }
            }
            Err(
                error @ StreamTableError::Stream(QuicStreamError::Flow(
                    FlowControlError::Exhausted { .. },
                )),
            ) => {
                observe_receive_result(
                    "receive STREAM frame segment",
                    table,
                    stream_id,
                    before_recv_remaining,
                    Err(error),
                );
                self.flow_control_violations.push(format!(
                    "Flow control violated for stream {} at offset {}",
                    stream_id.0, offset
                ));
            }
            Err(error) => observe_receive_result(
                "receive STREAM frame segment",
                table,
                stream_id,
                before_recv_remaining,
                Err(error),
            ),
        }
    }

    fn process_reset_stream(
        &mut self,
        stream_id: u64,
        error_code: u64,
        final_size: u64,
        table_id: u8,
    ) {
        let stream_id = StreamId(stream_id);
        let table = match self.stream_tables.get_mut(&table_id) {
            Some(table) => table,
            None => return,
        };

        ensure_remote_stream("accept remote stream for RESET_STREAM", table, stream_id);

        if let Ok(stream) = table.stream_mut(stream_id) {
            match stream.reset_send(error_code, final_size) {
                Ok(()) => {
                    observe_stream_reset_result("apply RESET_STREAM", stream_id, stream, Ok(()));
                    let state = self
                        .expected_stream_states
                        .entry(stream_id.0)
                        .or_insert_with(|| ExpectedStreamState {
                            id: stream_id,
                            direction: stream_id.direction(),
                            is_local: stream_id.is_local_for(self.role),
                            send_offset: stream.send_offset,
                            recv_offset: 0,
                            final_size: None,
                            is_reset: false,
                            reset_error_code: None,
                            stop_sending_error_code: None,
                        });

                    if state.is_reset
                        && let Some(prev_error_code) = state.reset_error_code
                        && prev_error_code != error_code
                    {
                        self.reset_transition_violations.push(format!(
                            "RESET_STREAM error code changed: stream {}, previous {}, new {}",
                            stream_id.0, prev_error_code, error_code
                        ));
                    }

                    state.is_reset = true;
                    state.reset_error_code = Some(error_code);
                    state.final_size = Some(final_size);
                }
                Err(QuicStreamError::InconsistentReset {
                    previous_final_size,
                    new_final_size,
                }) => {
                    observe_stream_reset_result(
                        "apply RESET_STREAM",
                        stream_id,
                        stream,
                        Err(QuicStreamError::InconsistentReset {
                            previous_final_size,
                            new_final_size,
                        }),
                    );
                    self.reset_transition_violations.push(format!(
                        "Inconsistent RESET_STREAM final size: stream {}, previous {}, new {}",
                        stream_id.0, previous_final_size, new_final_size
                    ));
                }
                Err(error) => {
                    observe_stream_reset_result("apply RESET_STREAM", stream_id, stream, Err(error))
                }
            }
        }
    }

    fn process_max_stream_data(&mut self, stream_id: u64, max_data: u64, table_id: u8) {
        let stream_id = StreamId(stream_id);
        let table = match self.stream_tables.get_mut(&table_id) {
            Some(table) => table,
            None => return,
        };

        ensure_remote_stream("accept remote stream for MAX_STREAM_DATA", table, stream_id);

        if let Ok(stream) = table.stream_mut(stream_id) {
            let before_limit = stream.send_credit.limit();
            let before_remaining = stream.send_credit.remaining();
            match stream.send_credit.increase_limit(max_data) {
                Ok(()) => {
                    assert!(
                        stream.send_credit.limit() >= before_limit,
                        "MAX_STREAM_DATA should not regress stream send limit"
                    );
                    assert!(
                        stream.send_credit.remaining() >= before_remaining,
                        "MAX_STREAM_DATA should not reduce remaining stream send credit"
                    );
                }
                Err(FlowControlError::LimitRegression { .. }) => {
                    observe_error(
                        "increase stream send credit from MAX_STREAM_DATA",
                        &FlowControlError::LimitRegression {
                            current: before_limit,
                            requested: max_data,
                        },
                    );
                    self.flow_control_violations.push(format!(
                        "MAX_STREAM_DATA limit regression for stream {}",
                        stream_id.0
                    ));
                }
                Err(error) => {
                    observe_error("increase stream send credit from MAX_STREAM_DATA", &error)
                }
            }
        }
    }

    fn test_fin_idempotency(
        &mut self,
        stream_id: u64,
        payload1: &[u8],
        payload2: &[u8],
        final_size: u64,
    ) {
        let stream_id = StreamId(stream_id);
        let table_id = 0;

        if let Some(table) = self.stream_tables.get_mut(&table_id) {
            ensure_remote_stream("accept remote stream for FIN idempotency", table, stream_id);

            // Send first payload with FIN
            let before_recv_remaining = table.connection_recv_remaining();
            let result = table.receive_stream_segment(stream_id, 0, payload1.len() as u64, true);
            observe_receive_result(
                "receive first FIN payload",
                table,
                stream_id,
                before_recv_remaining,
                result,
            );

            // Send second payload with FIN at same final size - should be idempotent
            let before_recv_remaining = table.connection_recv_remaining();
            let result2 = table.receive_stream_segment(
                stream_id,
                payload1.len() as u64,
                payload2.len() as u64,
                true,
            );
            let result2_ok = result2.is_ok();
            observe_receive_result(
                "receive second FIN payload",
                table,
                stream_id,
                before_recv_remaining,
                result2,
            );

            let expected_final = payload1.len() as u64 + payload2.len() as u64;
            if expected_final != final_size && result2_ok {
                self.fin_idempotency_violations.push(format!(
                    "FIN idempotency violation: stream {}, expected final size {}, computed {}",
                    stream_id.0, final_size, expected_final
                ));
            }
        }
    }

    fn test_flow_control_enforcement(
        &mut self,
        stream_id: u64,
        initial_window: u64,
        data_sequence: &[u64],
    ) {
        let stream_id = StreamId(stream_id);
        let table_id = 1;

        if let Some(table) = self.stream_tables.get_mut(&table_id) {
            ensure_remote_stream(
                "accept remote stream for flow-control test",
                table,
                stream_id,
            );

            if let Ok(stream) = table.stream_mut(stream_id) {
                // Set limited receive window
                stream.recv_credit =
                    asupersync::net::quic_native::streams::FlowCredit::new(initial_window);
            }

            let mut total_sent = 0u64;
            let mut violations = 0;

            for &data_len in data_sequence {
                if data_len == 0 {
                    continue;
                }

                let before_recv_remaining = table.connection_recv_remaining();
                let result = table.receive_stream_segment(stream_id, total_sent, data_len, false);
                match result {
                    Ok(()) => {
                        observe_receive_result(
                            "receive flow-control test segment",
                            table,
                            stream_id,
                            before_recv_remaining,
                            Ok(()),
                        );
                        total_sent += data_len;
                        if total_sent > initial_window {
                            violations += 1;
                        }
                    }
                    Err(error @ StreamTableError::Stream(QuicStreamError::Flow(_))) => {
                        observe_receive_result(
                            "receive flow-control test segment",
                            table,
                            stream_id,
                            before_recv_remaining,
                            Err(error),
                        );
                        // Expected flow control rejection
                        break;
                    }
                    Err(error) => {
                        observe_receive_result(
                            "receive flow-control test segment",
                            table,
                            stream_id,
                            before_recv_remaining,
                            Err(error),
                        );
                        // Other errors
                        break;
                    }
                }
            }

            if violations > 0 {
                self.flow_control_violations.push(format!(
                    "Flow control enforcement failed: stream {}, window {}, violations {}",
                    stream_id.0, initial_window, violations
                ));
            }
        }
    }

    fn validate_shadow_state_consistency(&self) {
        assert_eq!(
            self.connection_flow_limits,
            (MAX_FUZZ_WINDOW * 2, MAX_FUZZ_WINDOW * 2),
            "shadow connection-flow limits should remain stable"
        );
        if self.varint_overflow_detected {
            assert!(
                self.expected_stream_states
                    .values()
                    .all(|state| state.recv_offset <= QUIC_VARINT_MAX),
                "overflow detection should leave accepted receive offsets bounded"
            );
        }
        for violation in &self.flow_control_violations {
            assert!(
                !violation.is_empty(),
                "flow-control observations should include diagnostics"
            );
        }

        for (stream_id, state) in &self.expected_stream_states {
            assert_eq!(
                *stream_id, state.id.0,
                "shadow state key should match embedded stream ID"
            );
            assert_eq!(
                state.direction,
                state.id.direction(),
                "shadow direction should match stream ID encoding"
            );
            assert_eq!(
                state.is_local,
                state.id.is_local_for(self.role),
                "shadow locality should match endpoint role"
            );
            assert!(
                state.recv_offset <= state.final_size.unwrap_or(u64::MAX),
                "shadow receive offset should not exceed final size"
            );
            if state.is_reset {
                assert!(
                    state.reset_error_code.is_some(),
                    "reset shadow state should record an error code"
                );
            }
            if let Some(code) = state.stop_sending_error_code {
                assert!(
                    code <= QUIC_VARINT_MAX,
                    "STOP_SENDING error code should stay within varint range"
                );
            }
            assert!(
                state.send_offset <= QUIC_VARINT_MAX && state.recv_offset <= QUIC_VARINT_MAX,
                "shadow offsets should remain within QUIC varint range"
            );
        }
    }
}

fn encode_stream_frame(
    stream_id: u64,
    offset: u64,
    payload: &[u8],
    fin: bool,
    include_length: bool,
    include_offset: bool,
) -> Vec<u8> {
    let mut frame = Vec::new();

    // Frame type with flags
    let mut frame_type = STREAM_FRAME_TYPE_BASE;
    if fin {
        frame_type |= STREAM_FRAME_FIN_BIT;
    }
    if include_length {
        frame_type |= STREAM_FRAME_LEN_BIT;
    }
    if include_offset {
        frame_type |= STREAM_FRAME_OFF_BIT;
    }

    frame.push(frame_type);

    // Stream ID (varint)
    let mut temp_buf = Vec::new();
    if encode_varint(stream_id, &mut temp_buf).is_ok() {
        frame.extend_from_slice(&temp_buf);
    }

    // Offset (varint, if include_offset)
    if include_offset {
        temp_buf.clear();
        if encode_varint(offset, &mut temp_buf).is_ok() {
            frame.extend_from_slice(&temp_buf);
        }
    }

    // Length (varint, if include_length)
    if include_length {
        temp_buf.clear();
        if encode_varint(payload.len() as u64, &mut temp_buf).is_ok() {
            frame.extend_from_slice(&temp_buf);
        }
    }

    // Payload
    frame.extend_from_slice(payload);

    frame
}

fn encode_reset_stream_frame(stream_id: u64, error_code: u64, final_size: u64) -> Vec<u8> {
    let mut frame = Vec::new();
    frame.push(RESET_STREAM_FRAME_TYPE);

    let mut temp_buf = Vec::new();
    if encode_varint(stream_id, &mut temp_buf).is_ok() {
        frame.extend_from_slice(&temp_buf);
    }

    temp_buf.clear();
    if encode_varint(error_code, &mut temp_buf).is_ok() {
        frame.extend_from_slice(&temp_buf);
    }

    temp_buf.clear();
    if encode_varint(final_size, &mut temp_buf).is_ok() {
        frame.extend_from_slice(&temp_buf);
    }

    frame
}

fn encode_max_stream_data_frame(stream_id: u64, max_data: u64) -> Vec<u8> {
    let mut frame = Vec::new();
    frame.push(MAX_STREAM_DATA_FRAME_TYPE);

    let mut temp_buf = Vec::new();
    if encode_varint(stream_id, &mut temp_buf).is_ok() {
        frame.extend_from_slice(&temp_buf);
    }

    temp_buf.clear();
    if encode_varint(max_data, &mut temp_buf).is_ok() {
        frame.extend_from_slice(&temp_buf);
    }

    frame
}

fn encode_stop_sending_frame(stream_id: u64, error_code: u64) -> Vec<u8> {
    let mut frame = Vec::new();
    frame.push(STOP_SENDING_FRAME_TYPE);

    let mut temp_buf = Vec::new();
    if encode_varint(stream_id, &mut temp_buf).is_ok() {
        frame.extend_from_slice(&temp_buf);
    }

    temp_buf.clear();
    if encode_varint(error_code, &mut temp_buf).is_ok() {
        frame.extend_from_slice(&temp_buf);
    }

    frame
}

fn decode_stream_frame(data: &[u8]) -> Result<(u64, u64, usize, bool), QuicCoreError> {
    if data.is_empty() {
        return Err(QuicCoreError::UnexpectedEof);
    }

    let frame_type = data[0];
    if !(STREAM_FRAME_TYPE_BASE..=(STREAM_FRAME_TYPE_BASE | 0x07)).contains(&frame_type) {
        return Err(QuicCoreError::InvalidHeader("not a STREAM frame"));
    }

    let fin = (frame_type & STREAM_FRAME_FIN_BIT) != 0;
    let has_length = (frame_type & STREAM_FRAME_LEN_BIT) != 0;
    let has_offset = (frame_type & STREAM_FRAME_OFF_BIT) != 0;

    let mut pos = 1;

    // Decode stream ID
    if pos >= data.len() {
        return Err(QuicCoreError::UnexpectedEof);
    }
    let (stream_id, consumed) = decode_varint(&data[pos..])?;
    pos += consumed;

    // Decode offset
    let offset = if has_offset {
        if pos >= data.len() {
            return Err(QuicCoreError::UnexpectedEof);
        }
        let (offset, consumed) = decode_varint(&data[pos..])?;
        pos += consumed;
        offset
    } else {
        0
    };

    // Decode length
    let payload_len = if has_length {
        if pos >= data.len() {
            return Err(QuicCoreError::UnexpectedEof);
        }
        let (length, consumed) = decode_varint(&data[pos..])?;
        pos += consumed;
        let payload_len = usize::try_from(length)
            .map_err(|_| QuicCoreError::InvalidHeader("STREAM length does not fit usize"))?;
        let payload_end = pos
            .checked_add(payload_len)
            .ok_or(QuicCoreError::InvalidHeader(
                "STREAM payload length overflow",
            ))?;
        if payload_end > data.len() {
            return Err(QuicCoreError::UnexpectedEof);
        }
        payload_len
    } else {
        data.len() - pos
    };

    Ok((stream_id, offset, payload_len, fin))
}

fuzz_target!(|data: &[u8]| {
    if data.len() < 4 {
        return;
    }

    let mut unstructured = Unstructured::new(data);
    let operations: Result<Vec<QuicStreamOperation>, _> = (0..data.len().min(100))
        .map(|_| unstructured.arbitrary())
        .collect();

    let operations = match operations {
        Ok(ops) => ops,
        Err(_) => return,
    };

    let mut shadow_model = QuicStreamShadowModel::new();

    for operation in operations {
        match operation {
            QuicStreamOperation::SendStreamFrame {
                stream_id,
                offset,
                mut payload,
                fin,
                include_length,
                include_offset,
            } => {
                // Limit payload size for performance
                if payload.len() > MAX_FUZZ_PAYLOAD {
                    payload.truncate(MAX_FUZZ_PAYLOAD);
                }

                let frame_data = encode_stream_frame(
                    stream_id % 1000, // Limit stream ID space
                    offset % QUIC_VARINT_MAX,
                    &payload,
                    fin,
                    include_length,
                    include_offset,
                );

                // Test frame decoding
                if let Some((decoded_stream_id, decoded_offset, decoded_len, decoded_fin)) =
                    observe_decode_result(
                        "decode encoded STREAM frame",
                        decode_stream_frame(&frame_data),
                    )
                {
                    // Assertion 1: Stream ID bit encoding correctly decoded
                    let stream_id_obj = StreamId(decoded_stream_id);
                    let direction = stream_id_obj.direction();
                    let is_local = stream_id_obj.is_local_for(StreamRole::Client);
                    let expected_local_for_client = (decoded_stream_id & 0x1) == 0;
                    assert_eq!(
                        is_local, expected_local_for_client,
                        "Stream ID {} locality mismatch for client role",
                        decoded_stream_id
                    );

                    // Direction should be consistent with low bit 1
                    let expected_unidirectional = (decoded_stream_id & 0x2) != 0;
                    match direction {
                        StreamDirection::Unidirectional => {
                            assert!(
                                expected_unidirectional,
                                "Stream ID {} decoded as unidirectional but bit 1 is 0",
                                decoded_stream_id
                            );
                        }
                        StreamDirection::Bidirectional => {
                            assert!(
                                !expected_unidirectional,
                                "Stream ID {} decoded as bidirectional but bit 1 is 1",
                                decoded_stream_id
                            );
                        }
                    }

                    // Assertion 2: Varint offsets do not overflow
                    let Some(end_offset) = decoded_offset.checked_add(decoded_len as u64) else {
                        panic!(
                            "Offset + length overflowed u64: {}+{}",
                            decoded_offset, decoded_len
                        );
                    };
                    assert!(
                        end_offset <= QUIC_VARINT_MAX,
                        "Offset + length overflow: {}+{} > {}",
                        decoded_offset,
                        decoded_len,
                        QUIC_VARINT_MAX
                    );

                    shadow_model.process_stream_frame(
                        decoded_stream_id,
                        decoded_offset,
                        &payload[..decoded_len.min(payload.len())],
                        decoded_fin,
                        0,
                    );
                }
            }

            QuicStreamOperation::SendMalformedStreamFrame { raw_bytes } => {
                // Test robustness against malformed frames
                observe_decode_probe(
                    "decode malformed STREAM frame bytes",
                    decode_stream_frame(&raw_bytes),
                );
            }

            QuicStreamOperation::SendResetStreamFrame {
                stream_id,
                error_code,
                final_size,
            } => {
                let frame_data = encode_reset_stream_frame(
                    stream_id % 1000,
                    error_code,
                    final_size % QUIC_VARINT_MAX,
                );
                assert_eq!(
                    frame_data.first().copied(),
                    Some(RESET_STREAM_FRAME_TYPE),
                    "RESET_STREAM encoder should preserve the frame type"
                );

                // Assertion 6: RESET_STREAM transitions are valid
                shadow_model.process_reset_stream(
                    stream_id % 1000,
                    error_code,
                    final_size % QUIC_VARINT_MAX,
                    0,
                );
            }

            QuicStreamOperation::SendMaxStreamDataFrame {
                stream_id,
                max_data,
            } => {
                let frame_data =
                    encode_max_stream_data_frame(stream_id % 1000, max_data % QUIC_VARINT_MAX);
                assert_eq!(
                    frame_data.first().copied(),
                    Some(MAX_STREAM_DATA_FRAME_TYPE),
                    "MAX_STREAM_DATA encoder should preserve the frame type"
                );

                // Assertion 5: MAX_STREAM_DATA flow control enforced
                shadow_model.process_max_stream_data(
                    stream_id % 1000,
                    max_data % QUIC_VARINT_MAX,
                    0,
                );
            }

            QuicStreamOperation::SendStopSendingFrame {
                stream_id,
                error_code,
            } => {
                let stream_id = StreamId(stream_id % 1000);
                let frame_data = encode_stop_sending_frame(stream_id.0, error_code);
                assert_eq!(
                    frame_data.first().copied(),
                    Some(STOP_SENDING_FRAME_TYPE),
                    "STOP_SENDING encoder should preserve the frame type"
                );
                if let Some(table) = shadow_model.stream_tables.get_mut(&0) {
                    ensure_remote_stream("accept remote stream for STOP_SENDING", table, stream_id);
                    match table.stream_mut(stream_id) {
                        Ok(stream) => {
                            stream.on_stop_sending(error_code);
                            assert!(
                                stream.stop_sending_error_code.is_some(),
                                "STOP_SENDING should record an error code"
                            );
                        }
                        Err(error) => observe_error("lookup stream for STOP_SENDING", &error),
                    }
                }
            }

            QuicStreamOperation::TestStreamIdEncoding {
                role,
                direction,
                sequence,
            } => {
                // Assertion 1: Stream ID bit encoding correctly decoded
                shadow_model.validate_stream_id_encoding(role, direction, sequence % (1u64 << 62));
            }

            QuicStreamOperation::TestVarintOverflow {
                base_offset,
                length,
            } => {
                // Assertion 2: Varint offsets do not overflow
                shadow_model.validate_varint_overflow(
                    base_offset % QUIC_VARINT_MAX,
                    length % QUIC_VARINT_MAX,
                );
            }

            QuicStreamOperation::TestFinIdempotency {
                stream_id,
                payload1,
                payload2,
                final_size,
            } => {
                // Assertion 3: FIN flag operations are idempotent
                if payload1.len() + payload2.len() <= MAX_FUZZ_PAYLOAD {
                    shadow_model.test_fin_idempotency(
                        stream_id % 1000,
                        &payload1,
                        &payload2,
                        final_size % QUIC_VARINT_MAX,
                    );
                }
            }

            QuicStreamOperation::TestFlowControlEnforcement {
                stream_id,
                initial_window,
                data_sequence,
            } => {
                // Assertion 5: MAX_STREAM_DATA flow control enforced
                let limited_sequence: Vec<u64> = data_sequence
                    .iter()
                    .take(20)
                    .map(|&len| len % 10000)
                    .collect();
                shadow_model.test_flow_control_enforcement(
                    stream_id % 1000,
                    initial_window % MAX_FUZZ_WINDOW,
                    &limited_sequence,
                );
            }

            QuicStreamOperation::TestResetTransitions {
                stream_id,
                write_data_len,
                reset_final_size,
                error_code,
                second_reset_final_size,
            } => {
                // Assertion 6: RESET_STREAM transitions are valid
                let stream_id = StreamId(stream_id % 1000);
                if let Some(table) = shadow_model.stream_tables.get_mut(&2) {
                    ensure_remote_stream(
                        "accept remote stream for reset-transition test",
                        table,
                        stream_id,
                    );

                    // Write some data first
                    let write_len = write_data_len % 10000;
                    let before_send_remaining = table.connection_send_remaining();
                    let write_result = table.write_stream(stream_id, write_len);
                    observe_write_result(
                        "write before reset-transition test",
                        table,
                        stream_id,
                        before_send_remaining,
                        write_result,
                    );

                    // Reset stream
                    match table.stream_mut(stream_id) {
                        Ok(stream) => {
                            let reset_result =
                                stream.reset_send(error_code, reset_final_size % QUIC_VARINT_MAX);
                            observe_stream_reset_result(
                                "apply reset-transition test reset",
                                stream_id,
                                stream,
                                reset_result,
                            );

                            // Try second reset with potentially different final size
                            if let Some(second_final_size) = second_reset_final_size {
                                let result = stream
                                    .reset_send(error_code, second_final_size % QUIC_VARINT_MAX);
                                observe_stream_reset_result(
                                    "apply reset-transition test second reset",
                                    stream_id,
                                    stream,
                                    result,
                                );
                            }
                        }
                        Err(error) => {
                            observe_error("lookup stream for reset-transition test", &error)
                        }
                    }
                }
            }
        }
    }

    // Final assertions about invariant violations

    // Assertion 1: No stream ID encoding violations
    assert!(
        shadow_model.stream_id_encoding_violations.is_empty(),
        "Stream ID encoding violations: {:?}",
        shadow_model.stream_id_encoding_violations
    );

    // Assertion 2: No varint overflow should be processed successfully
    // (overflow detection is OK, but processing overflowed values is not)

    // Assertion 3: FIN flag must be idempotent
    assert!(
        shadow_model.fin_idempotency_violations.is_empty(),
        "FIN idempotency violations: {:?}",
        shadow_model.fin_idempotency_violations
    );

    // Assertion 5: Flow control must be enforced
    // Note: Some violations are expected in fuzzing, but they should be caught by the implementation

    // Assertion 6: RESET_STREAM transitions must be valid
    assert!(
        shadow_model.reset_transition_violations.is_empty(),
        "RESET_STREAM transition violations: {:?}",
        shadow_model.reset_transition_violations
    );

    shadow_model.validate_shadow_state_consistency();
});
