#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use asupersync::database::mysql::{MySqlError, fuzz_decode_packet_header, fuzz_parse_error_packet};
use libfuzzer_sys::fuzz_target;

const MAX_CASES: usize = 32;
const MAX_MESSAGE_LEN: usize = 512;
const MAX_PACKET_LEN_24BIT: u32 = 0x00FF_FFFF;

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
