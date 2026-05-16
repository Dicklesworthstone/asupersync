#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use asupersync::database::mysql::{MySqlError, fuzz_decode_packet_header, fuzz_parse_error_packet};
use libfuzzer_sys::fuzz_target;
use std::sync::OnceLock;

const MAX_CASES: usize = 32;
const MAX_MESSAGE_LEN: usize = 512;
const MAX_PACKET_LEN_24BIT: u32 = 0x00FF_FFFF;

static FIXED_CANARIES: OnceLock<()> = OnceLock::new();

#[derive(Debug, Arbitrary)]
struct FuzzInput {
    header_cases: Vec<HeaderCase>,
    error_cases: Vec<ErrorCase>,
}

#[derive(Debug, Arbitrary)]
enum HeaderCase {
    Structured {
        length: u32,
        sequence: u8,
        expected_sequence: u8,
    },
    Raw {
        header: [u8; 4],
        expected_sequence: u8,
    },
}

#[derive(Debug, Arbitrary)]
struct ErrorCase {
    marker: u8,
    code: u16,
    include_sql_state: bool,
    sql_state: [u8; 5],
    message: Vec<u8>,
    truncate_to: Option<u16>,
}

fuzz_target!(|data: &[u8]| {
    FIXED_CANARIES.get_or_init(assert_fixed_packet_error_canaries);

    let Ok(mut input) = FuzzInput::arbitrary(&mut Unstructured::new(data)) else {
        return;
    };

    input.header_cases.truncate(MAX_CASES);
    input.error_cases.truncate(MAX_CASES);

    for case in input.header_cases {
        run_header_case(case);
    }

    for case in input.error_cases {
        run_error_case(case);
    }
});

fn run_header_case(case: HeaderCase) {
    let (header, expected_sequence) = match case {
        HeaderCase::Structured {
            length,
            sequence,
            expected_sequence,
        } => {
            let length = length & MAX_PACKET_LEN_24BIT;
            (
                [
                    (length & 0xFF) as u8,
                    ((length >> 8) & 0xFF) as u8,
                    ((length >> 16) & 0xFF) as u8,
                    sequence,
                ],
                expected_sequence,
            )
        }
        HeaderCase::Raw {
            header,
            expected_sequence,
        } => (header, expected_sequence),
    };

    let expected_length =
        u32::from(header[0]) | (u32::from(header[1]) << 8) | (u32::from(header[2]) << 16);

    match fuzz_decode_packet_header(header, expected_sequence) {
        Ok((decoded_length, decoded_sequence)) => {
            assert_eq!(decoded_length, expected_length);
            assert_eq!(decoded_sequence, header[3]);
            assert_eq!(decoded_sequence, expected_sequence);
        }
        Err(MySqlError::Protocol(message)) => {
            assert_ne!(header[3], expected_sequence);
            assert!(
                message.contains("packet sequence mismatch"),
                "unexpected protocol error: {message}"
            );
        }
        Err(other) => panic!("unexpected header parser result: {other:?}"),
    }
}

fn run_error_case(mut case: ErrorCase) {
    case.message.truncate(MAX_MESSAGE_LEN);

    let mut packet = Vec::with_capacity(1 + 2 + 1 + 5 + case.message.len());
    packet.push(case.marker);
    packet.extend_from_slice(&case.code.to_le_bytes());
    if case.include_sql_state {
        packet.push(b'#');
        packet.extend_from_slice(&case.sql_state);
    }
    packet.extend_from_slice(&case.message);

    if let Some(truncate_to) = case.truncate_to {
        packet.truncate(usize::from(truncate_to).min(packet.len()));
    }

    match fuzz_parse_error_packet(&packet) {
        MySqlError::Protocol(message) => {
            assert!(
                case.marker != 0xFF || packet.len() < 3,
                "real ERR packet should not downgrade to Protocol: {message}"
            );
        }
        MySqlError::Server {
            code,
            sql_state,
            message,
        } => {
            assert_eq!(case.marker, 0xFF);
            assert!(packet.len() >= 3);
            assert_eq!(code, case.code);
            assert_eq!(sql_state, expected_sql_state(&packet));
            assert_eq!(message, expected_message(&packet));
        }
        other => panic!("unexpected error packet result: {other:?}"),
    }
}

fn assert_fixed_packet_error_canaries() {
    assert_header_protocol_rejection(
        [0, 0, 0, 7],
        8,
        "packet sequence mismatch: expected 8, got 7",
    );
    assert_error_packet_protocol_rejection(&[], "not an error packet");
    assert_error_packet_protocol_rejection(&[0x00, 0x34, 0x12], "not an error packet");
    assert_error_packet_protocol_rejection(&[0xFF], "unexpected end of packet");
    assert_error_packet_protocol_rejection(&[0xFF, 0x34], "unexpected end of packet");

    assert_error_packet_server_diagnostic(
        &[
            0xFF, 0x34, 0x12, b'#', b'H', b'Y', b'0', b'0', b'1', b'o', b'o', b'p', b's',
        ],
        0x1234,
        "HY001",
        "oops",
    );
    assert_error_packet_server_diagnostic(
        &[0xFF, 0x34, 0x12, b'o', b'o', b'p', b's'],
        0x1234,
        "HY000",
        "oops",
    );
}

fn assert_header_protocol_rejection(header: [u8; 4], expected_sequence: u8, expected: &str) {
    let error = fuzz_decode_packet_header(header, expected_sequence)
        .expect_err("fixed packet-header canary should reject");
    assert_mysql_protocol_error(error, expected);
}

fn assert_error_packet_protocol_rejection(packet: &[u8], expected: &str) {
    assert_mysql_protocol_error(fuzz_parse_error_packet(packet), expected);
}

fn assert_mysql_protocol_error(error: MySqlError, expected: &str) {
    match &error {
        MySqlError::Protocol(message) => assert_eq!(
            message, expected,
            "MySQL protocol diagnostic payload changed"
        ),
        other => panic!("expected MySQL protocol error, got {other:?}"),
    }

    assert_eq!(
        error.to_string(),
        format!("MySQL protocol error: {expected}"),
        "MySQL protocol Display diagnostic changed"
    );
}

fn assert_error_packet_server_diagnostic(
    packet: &[u8],
    expected_code: u16,
    expected_sql_state: &str,
    expected_message: &str,
) {
    let error = fuzz_parse_error_packet(packet);
    match &error {
        MySqlError::Server {
            code,
            sql_state,
            message,
        } => {
            assert_eq!(*code, expected_code, "MySQL ERR packet code changed");
            assert_eq!(
                sql_state, expected_sql_state,
                "MySQL ERR packet SQL state changed"
            );
            assert_eq!(
                message, expected_message,
                "MySQL ERR packet message changed"
            );
        }
        other => panic!("expected MySQL server error packet, got {other:?}"),
    }

    assert_eq!(
        error.to_string(),
        format!("MySQL error [{expected_code}] ({expected_sql_state}): {expected_message}"),
        "MySQL server Display diagnostic changed"
    );
}

fn expected_sql_state(packet: &[u8]) -> String {
    if packet.get(3) == Some(&b'#') && packet.len() >= 9 {
        std::str::from_utf8(&packet[4..9])
            .unwrap_or("HY000")
            .to_string()
    } else {
        "HY000".to_string()
    }
}

fn expected_message(packet: &[u8]) -> String {
    let message_bytes = if packet.get(3) == Some(&b'#') {
        if packet.len() >= 9 {
            &packet[9..]
        } else if packet.len() > 4 {
            &packet[4..]
        } else {
            &[]
        }
    } else if packet.len() > 3 {
        &packet[3..]
    } else {
        &[]
    };

    std::str::from_utf8(message_bytes)
        .unwrap_or("unknown error")
        .to_string()
}
