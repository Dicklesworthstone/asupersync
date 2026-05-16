//! Fuzz target for MySQL wire protocol packet parsing.
//!
//! Tests malformed MySQL wire protocol packets to ensure robust parsing:
//! 1. Packet length field (24-bit LE) + sequence ID correctly parsed
//! 2. Maximum packet length boundary handled through the real header decoder
//! 3. Command phase packet shapes remain valid MySQL packets
//! 4. Result set column-count length encoding flows through the OK-packet parser
//! 5. EOF/OK/error packet discrimination reaches the real parser seams
//!
//! # Attack vectors tested:
//! - Malformed packet headers (corrupted length, invalid sequence)
//! - Maximum-size packet headers
//! - Invalid command byte values in command phase packets
//! - Column count integer encoding boundary conditions
//! - Ambiguous EOF/OK packet structures
//!
//! # Running
//! ```bash
//! cargo +nightly fuzz run mysql_wire
//! ```

#![no_main]

use arbitrary::Arbitrary;
use asupersync::database::MySqlError;
use asupersync::database::mysql::{
    ToSql, fuzz_build_stmt_execute_packet, fuzz_decode_packet_header,
    fuzz_parse_data_row_or_terminator, fuzz_parse_error_packet, fuzz_parse_ok_packet_fields,
};
use libfuzzer_sys::fuzz_target;
use std::sync::OnceLock;

/// Maximum input size to prevent memory exhaustion during fuzzing.
const MAX_INPUT_SIZE: usize = 100_000;

/// MySQL packet header size (3 bytes length + 1 byte sequence).
const PACKET_HEADER_SIZE: usize = 4;

/// MySQL maximum packet size (16MB - 1 byte).
const MAX_PACKET_SIZE: u32 = 16_777_215;

static FIXED_REGRESSIONS: OnceLock<()> = OnceLock::new();

/// MySQL command constants for command phase testing.
mod command {
    pub const COM_QUIT: u8 = 0x01;
    pub const COM_INIT_DB: u8 = 0x02;
    pub const COM_QUERY: u8 = 0x03;
    pub const COM_FIELD_LIST: u8 = 0x04;
    pub const COM_PING: u8 = 0x0E;
    pub const COM_STMT_PREPARE: u8 = 0x16;
    pub const COM_STMT_EXECUTE: u8 = 0x17;
    pub const COM_STMT_CLOSE: u8 = 0x19;
}

/// Fuzzing scenarios for different protocol aspects.
#[derive(Arbitrary, Debug, Clone)]
enum FuzzScenario {
    /// Test packet header parsing with potential corruption.
    PacketHeader {
        /// Raw 4-byte header (3 bytes length LE + 1 byte sequence).
        header: [u8; 4],
        /// Expected sequence number for validation.
        expected_sequence: u8,
    },
    /// Test command phase packet shape.
    CommandPhase {
        /// Command byte (COM_QUERY, COM_PREPARE, etc.).
        command: u8,
        /// Command payload data.
        payload: Vec<u8>,
    },
    /// Test result set column count encoding.
    ColumnCount {
        /// Length-encoded integer representing column count.
        encoded_count: Vec<u8>,
    },
    /// Test EOF vs OK packet discrimination.
    EofOkDiscrimination {
        /// Packet data that may be EOF (0xFE, len<9) or OK (0x00).
        packet_data: Vec<u8>,
    },
    /// Test maximum packet-length boundary.
    PacketLengthBoundary {
        /// 24-bit length field.
        length_bytes: [u8; 3],
        /// Sequence byte.
        sequence: u8,
    },
}

fuzz_target!(|data: &[u8]| {
    FIXED_REGRESSIONS.get_or_init(test_fixed_real_seam_regressions);

    // Guard against excessively large inputs
    if data.len() > MAX_INPUT_SIZE {
        return;
    }

    // Try to parse input as an arbitrary fuzz scenario
    if let Ok(scenario) = arbitrary::Unstructured::new(data).arbitrary::<FuzzScenario>() {
        test_scenario(scenario);
    }

    // Also test raw packet data directly
    test_raw_packet_data(data);
});

/// Test a specific fuzzing scenario.
fn test_scenario(scenario: FuzzScenario) {
    match scenario {
        FuzzScenario::PacketHeader {
            header,
            expected_sequence,
        } => {
            test_packet_header_parsing(header, expected_sequence);
        }
        FuzzScenario::CommandPhase { command, payload } => {
            test_command_dispatch(command, payload);
        }
        FuzzScenario::ColumnCount { encoded_count } => {
            test_column_count_parsing(encoded_count);
        }
        FuzzScenario::EofOkDiscrimination { packet_data } => {
            test_eof_ok_discrimination(packet_data);
        }
        FuzzScenario::PacketLengthBoundary {
            length_bytes,
            sequence,
        } => {
            test_packet_length_boundary(length_bytes, sequence);
        }
    }
}

/// Test packet header parsing (Assertion 1: 24-bit LE length + sequence ID).
fn test_packet_header_parsing(header: [u8; 4], expected_sequence: u8) {
    let length = packet_length(header);
    let result = fuzz_decode_packet_header(header, expected_sequence);

    if header[3] == expected_sequence {
        let (decoded_len, decoded_seq) =
            result.expect("valid 24-bit MySQL packet header must decode");
        assert_eq!(decoded_len, length);
        assert_eq!(decoded_seq, expected_sequence);
        assert!(decoded_len <= MAX_PACKET_SIZE);
    } else {
        expect_sequence_mismatch_err(result, expected_sequence, header[3]);
    }
}

/// Test command phase packet shape (Assertion 3: COM_* packet framing).
fn test_command_dispatch(command: u8, payload: Vec<u8>) {
    let known_commands = [
        command::COM_QUIT,
        command::COM_INIT_DB,
        command::COM_QUERY,
        command::COM_FIELD_LIST,
        command::COM_PING,
        command::COM_STMT_PREPARE,
        command::COM_STMT_EXECUTE,
        command::COM_STMT_CLOSE,
    ];

    let payload_len = payload.len().saturating_add(1);
    if payload_len > MAX_PACKET_SIZE as usize {
        return;
    }

    let header = packet_header(payload_len as u32, 0);
    let (decoded_len, decoded_seq) =
        fuzz_decode_packet_header(header, 0).expect("framed command packet must decode");
    assert_eq!(decoded_len as usize, payload_len);
    assert_eq!(decoded_seq, 0);

    let mut command_payload = Vec::with_capacity(payload_len);
    command_payload.push(command);
    command_payload.extend_from_slice(&payload);

    if known_commands.contains(&command) {
        exercise_payload_parsers(&command_payload);
    } else {
        observe_error_packet(&command_payload);
    }
}

/// Test column count parsing (Assertion 4: result set column-count length encoding).
fn test_column_count_parsing(encoded_count: Vec<u8>) {
    if encoded_count.is_empty() {
        return;
    }

    let packet = ok_packet_with_affected_rows(&encoded_count);
    observe_ok_packet_fields(&packet);
}

/// Test EOF vs OK packet discrimination (Assertion 5: discrimination by length).
fn test_eof_ok_discrimination(packet_data: Vec<u8>) {
    if packet_data.is_empty() {
        return;
    }

    let terminator_result = fuzz_parse_data_row_or_terminator(&packet_data, &[], true);

    if packet_data[0] == 0xFE && packet_data.len() < 9 {
        assert!(matches!(terminator_result, Ok(None)));
    }
    if packet_data[0] == 0x00 {
        observe_ok_packet_fields(&packet_data);
    }
    if packet_data[0] == 0xFF {
        observe_error_packet(&packet_data);
    }
}

/// Test maximum packet length boundary (Assertion 2: 24-bit packet lengths).
fn test_packet_length_boundary(length_bytes: [u8; 3], sequence: u8) {
    let length = u32::from(length_bytes[0])
        | (u32::from(length_bytes[1]) << 8)
        | (u32::from(length_bytes[2]) << 16);
    let header = [length_bytes[0], length_bytes[1], length_bytes[2], sequence];

    let (decoded_len, decoded_seq) =
        fuzz_decode_packet_header(header, sequence).expect("24-bit packet length must decode");
    assert_eq!(decoded_len, length);
    assert_eq!(decoded_seq, sequence);
    assert!(decoded_len <= MAX_PACKET_SIZE);
}

/// Test raw packet data for edge cases.
fn test_raw_packet_data(data: &[u8]) {
    if data.len() < PACKET_HEADER_SIZE {
        return;
    }

    let header: [u8; 4] = data[0..4].try_into().unwrap();
    let payload = &data[4..];
    let (declared_len, _) =
        fuzz_decode_packet_header(header, header[3]).expect("raw packet header must decode");

    if payload.len() >= declared_len as usize {
        exercise_payload_parsers(&payload[..declared_len as usize]);
    } else {
        exercise_payload_parsers(payload);
    }
}

fn packet_length(header: [u8; 4]) -> u32 {
    u32::from(header[0]) | (u32::from(header[1]) << 8) | (u32::from(header[2]) << 16)
}

fn packet_header(length: u32, sequence: u8) -> [u8; 4] {
    [
        (length & 0xFF) as u8,
        ((length >> 8) & 0xFF) as u8,
        ((length >> 16) & 0xFF) as u8,
        sequence,
    ]
}

fn ok_packet_with_affected_rows(encoded_affected_rows: &[u8]) -> Vec<u8> {
    let mut packet = Vec::with_capacity(encoded_affected_rows.len() + 6);
    packet.push(0x00);
    packet.extend_from_slice(encoded_affected_rows);
    packet.push(0x00);
    packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
    packet
}

fn exercise_payload_parsers(payload: &[u8]) {
    match payload.first() {
        Some(0x00) => {
            observe_ok_packet_fields(payload);
            observe_data_row_or_terminator(payload, true);
        }
        Some(0xFE) => {
            observe_data_row_or_terminator(payload, true);
        }
        Some(0xFF) => {
            observe_error_packet(payload);
        }
        Some(_) => {
            observe_data_row_or_terminator(payload, false);
        }
        None => {}
    }
}

fn observe_ok_packet_fields(packet: &[u8]) {
    match fuzz_parse_ok_packet_fields(packet) {
        Ok((affected_rows, status_flags)) => {
            assert_eq!(packet.first(), Some(&0x00));

            let mut pos = 1;
            let expected_affected_rows =
                scan_lenenc_int(packet, &mut pos).expect("successful OK packet exposes rows");
            let _last_insert_id =
                scan_lenenc_int(packet, &mut pos).expect("successful OK packet exposes insert id");
            assert!(
                pos + 4 <= packet.len(),
                "successful OK packet must contain status and warning fields"
            );
            let expected_status = u16::from_le_bytes([packet[pos], packet[pos + 1]]);

            assert_eq!(affected_rows, expected_affected_rows);
            assert_eq!(status_flags, expected_status);
        }
        Err(error) => assert_observable_mysql_error(&error),
    }
}

fn observe_error_packet(packet: &[u8]) {
    let error = fuzz_parse_error_packet(packet);
    match &error {
        MySqlError::Server {
            code, sql_state, ..
        } => {
            assert_eq!(packet.first(), Some(&0xFF));
            assert!(packet.len() >= 3);
            assert_eq!(*code, u16::from_le_bytes([packet[1], packet[2]]));
            assert_eq!(sql_state.len(), 5);
        }
        MySqlError::Protocol(message) => {
            assert!(!message.is_empty());
            assert!(
                packet.first() != Some(&0xFF) || packet.len() < 3,
                "0xFF packets with an error code should classify as server errors"
            );
        }
        other => assert_observable_mysql_error(other),
    }
}

fn observe_data_row_or_terminator(payload: &[u8], deprecate_eof: bool) {
    match fuzz_parse_data_row_or_terminator(payload, &[], deprecate_eof) {
        Ok(None) => {
            assert!(
                is_short_eof_packet(payload) || (deprecate_eof && is_ok_like_terminator(payload)),
                "terminator classification must be backed by EOF or OK-like packet shape"
            );
        }
        Ok(Some(values)) => {
            assert!(values.is_empty());
            assert!(
                payload.is_empty(),
                "zero-column text rows should only consume an empty payload"
            );
        }
        Err(error) => assert_observable_mysql_error(&error),
    }
}

fn scan_lenenc_int(data: &[u8], pos: &mut usize) -> Option<u64> {
    let first = *data.get(*pos)?;
    *pos += 1;
    match first {
        0..=250 => Some(u64::from(first)),
        0xFC => {
            let bytes = [*data.get(*pos)?, *data.get(*pos + 1)?];
            *pos += 2;
            Some(u64::from(u16::from_le_bytes(bytes)))
        }
        0xFD => {
            let b0 = u64::from(*data.get(*pos)?);
            let b1 = u64::from(*data.get(*pos + 1)?);
            let b2 = u64::from(*data.get(*pos + 2)?);
            *pos += 3;
            Some(b0 | (b1 << 8) | (b2 << 16))
        }
        0xFE => {
            let bytes: [u8; 8] = data.get(*pos..*pos + 8)?.try_into().ok()?;
            *pos += 8;
            Some(u64::from_le_bytes(bytes))
        }
        0xFB => None,
        _ => None,
    }
}

fn is_short_eof_packet(payload: &[u8]) -> bool {
    payload.first() == Some(&0xFE) && payload.len() < 9
}

fn is_ok_like_terminator(payload: &[u8]) -> bool {
    if !matches!(payload.first(), Some(0x00 | 0xFE)) {
        return false;
    }

    let mut pos = 1;
    scan_lenenc_int(payload, &mut pos).is_some()
        && scan_lenenc_int(payload, &mut pos).is_some()
        && pos + 4 <= payload.len()
}

fn assert_observable_mysql_error(error: &MySqlError) {
    let rendered = error.to_string();
    assert!(!rendered.is_empty());
}

fn expect_sequence_mismatch_err<T>(
    result: Result<T, MySqlError>,
    expected_seq: u8,
    actual_seq: u8,
) {
    match result {
        Err(MySqlError::Protocol(message)) => {
            assert_eq!(
                message,
                format!("packet sequence mismatch: expected {expected_seq}, got {actual_seq}")
            );
        }
        Err(other) => panic!("expected protocol error, got {other:?}"),
        Ok(_) => panic!("expected protocol error"),
    }
}

fn test_fixed_real_seam_regressions() {
    let (len, seq) = fuzz_decode_packet_header([0xFF, 0xFF, 0xFF, 0x07], 0x07)
        .expect("maximum 24-bit packet length must decode");
    assert_eq!(len, MAX_PACKET_SIZE);
    assert_eq!(seq, 0x07);

    expect_sequence_mismatch_err(
        fuzz_decode_packet_header([0x01, 0x00, 0x00, 0x02], 0x01),
        0x01,
        0x02,
    );

    let single_byte_ok = ok_packet_with_affected_rows(&[0xFA]);
    let (affected_rows, status_flags) =
        fuzz_parse_ok_packet_fields(&single_byte_ok).expect("single-byte lenenc OK packet");
    assert_eq!(affected_rows, 250);
    assert_eq!(status_flags, 0);

    let two_byte_ok = ok_packet_with_affected_rows(&[0xFC, 0x00, 0x01]);
    let (affected_rows, status_flags) =
        fuzz_parse_ok_packet_fields(&two_byte_ok).expect("two-byte lenenc OK packet");
    assert_eq!(affected_rows, 256);
    assert_eq!(status_flags, 0);

    assert!(
        fuzz_parse_ok_packet_fields(&ok_packet_with_affected_rows(&[0xFF])).is_err(),
        "reserved length-encoded prefix must be rejected by the real parser"
    );

    assert!(matches!(
        fuzz_parse_data_row_or_terminator(&[0xFE, 0x00, 0x00, 0x00, 0x00], &[], true),
        Ok(None)
    ));

    match fuzz_parse_error_packet(&[0xFF, 0x48, 0x04, b'#', b'H', b'Y', b'0', b'0', b'0']) {
        MySqlError::Server {
            code, sql_state, ..
        } => {
            assert_eq!(code, 0x0448);
            assert_eq!(sql_state, "HY000");
        }
        other => panic!("expected server error packet, got {other:?}"),
    }

    let params: [&dyn ToSql; 0] = [];
    let packet = fuzz_build_stmt_execute_packet(0xAABB_CCDD, &params)
        .expect("empty COM_STMT_EXECUTE packet must build");
    let header: [u8; 4] = packet[0..4].try_into().unwrap();
    let (payload_len, packet_seq) =
        fuzz_decode_packet_header(header, 0).expect("built statement packet header must decode");
    assert_eq!(payload_len as usize, packet.len() - PACKET_HEADER_SIZE);
    assert_eq!(packet_seq, 0);
    assert_eq!(packet[PACKET_HEADER_SIZE], command::COM_STMT_EXECUTE);
}
