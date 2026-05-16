#![no_main]

//! Structure-aware fuzz target for PostgreSQL StartupMessage parsing.
//!
//! Bead: br-asupersync-7b0zcm
//!
//! The startup packet is length-prefixed, carries protocol version 3.0, then
//! NUL-delimited parameter name/value pairs and a final NUL terminator. This
//! target drives the production parser seam with valid packets, embedded-NUL
//! smuggling shapes, duplicate keys, unterminated pairs, length mismatches, and
//! arbitrary bytes.

use arbitrary::{Arbitrary, Unstructured};
use asupersync::database::postgres::{PgError, fuzz_parse_startup_message};
use libfuzzer_sys::fuzz_target;
use std::hint::black_box;
use std::sync::OnceLock;

const MAX_FIELD_BYTES: usize = 64;
const MAX_EXTRA_PARAMS: usize = 8;
const MAX_PACKET_BYTES: usize = 2048;
const POSTGRES_PROTOCOL_VERSION_3_0: i32 = 196_608;

static FIXED_CANARIES: OnceLock<()> = OnceLock::new();

#[derive(Debug, Clone, Arbitrary)]
struct StartupInput {
    scenario: StartupScenario,
}

#[derive(Debug, Clone, Arbitrary)]
enum StartupScenario {
    Valid {
        extra_params: Vec<GeneratedParam>,
        include_database: bool,
        empty_application_name: bool,
    },
    EmbeddedNulKey,
    EmbeddedNulValue,
    DuplicateKey,
    UnterminatedPair,
    LengthMismatch {
        delta: u8,
    },
    EmptyKeyTrailingPayload,
    RawBytes {
        bytes: Vec<u8>,
    },
}

#[derive(Debug, Clone, Arbitrary)]
struct GeneratedParam {
    name_seed: Vec<u8>,
    value_seed: Vec<u8>,
}

#[derive(Debug)]
struct StartupPacket {
    bytes: Vec<u8>,
    mutation_label: &'static str,
    expected: ExpectedOutcome,
    offending_field_index: Option<usize>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExpectedOutcome {
    Accept,
    Reject,
    Unconstrained,
}

#[derive(Debug)]
#[allow(dead_code)]
struct StartupLabels {
    packet_len: usize,
    declared_len: Option<i32>,
    param_count: usize,
    offending_field_index: Option<usize>,
    mutation_label: &'static str,
    error_kind: &'static str,
    accepted: bool,
    authentication_reached: bool,
}

impl StartupScenario {
    fn into_packet(self) -> StartupPacket {
        match self {
            StartupScenario::Valid {
                extra_params,
                include_database,
                empty_application_name,
            } => {
                let mut fields = vec![(b"user".to_vec(), b"fuzz_user".to_vec())];
                if include_database {
                    fields.push((b"database".to_vec(), b"fuzz_db".to_vec()));
                }
                if empty_application_name {
                    fields.push((b"application_name".to_vec(), Vec::new()));
                }
                for (idx, param) in extra_params.into_iter().take(MAX_EXTRA_PARAMS).enumerate() {
                    fields.push((
                        generated_param_name(idx, &param.name_seed),
                        generated_param_value(&param.value_seed),
                    ));
                }
                StartupPacket {
                    bytes: startup_packet_from_fields(&fields, true),
                    mutation_label: "valid",
                    expected: ExpectedOutcome::Accept,
                    offending_field_index: None,
                }
            }
            StartupScenario::EmbeddedNulKey => StartupPacket {
                bytes: startup_packet_from_fields(
                    &[(b"us\0er".to_vec(), b"fuzz_user".to_vec())],
                    true,
                ),
                mutation_label: "embedded_nul_key",
                expected: ExpectedOutcome::Reject,
                offending_field_index: Some(0),
            },
            StartupScenario::EmbeddedNulValue => StartupPacket {
                bytes: startup_packet_from_fields(
                    &[(b"user".to_vec(), b"fuzz\0user\0admin".to_vec())],
                    true,
                ),
                mutation_label: "embedded_nul_value",
                expected: ExpectedOutcome::Reject,
                offending_field_index: Some(1),
            },
            StartupScenario::DuplicateKey => StartupPacket {
                bytes: startup_packet_from_fields(
                    &[
                        (b"user".to_vec(), b"fuzz_user".to_vec()),
                        (b"user".to_vec(), b"admin".to_vec()),
                    ],
                    true,
                ),
                mutation_label: "duplicate_key",
                expected: ExpectedOutcome::Reject,
                offending_field_index: Some(2),
            },
            StartupScenario::UnterminatedPair => StartupPacket {
                bytes: startup_packet_from_fields(
                    &[
                        (b"user".to_vec(), b"fuzz_user".to_vec()),
                        (b"database".to_vec(), Vec::new()),
                    ],
                    false,
                ),
                mutation_label: "unterminated_pair",
                expected: ExpectedOutcome::Reject,
                offending_field_index: Some(2),
            },
            StartupScenario::LengthMismatch { delta } => {
                let mut bytes =
                    startup_packet_from_fields(&[(b"user".to_vec(), b"fuzz_user".to_vec())], true);
                let declared = i32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
                let adjusted = declared.saturating_add(i32::from(delta.max(1)));
                bytes[0..4].copy_from_slice(&adjusted.to_be_bytes());
                StartupPacket {
                    bytes,
                    mutation_label: "length_mismatch",
                    expected: ExpectedOutcome::Reject,
                    offending_field_index: None,
                }
            }
            StartupScenario::EmptyKeyTrailingPayload => {
                let mut body = POSTGRES_PROTOCOL_VERSION_3_0.to_be_bytes().to_vec();
                body.push(0);
                body.extend_from_slice(b"smuggled");
                StartupPacket {
                    bytes: startup_packet_from_body(body),
                    mutation_label: "empty_key_trailing_payload",
                    expected: ExpectedOutcome::Reject,
                    offending_field_index: Some(0),
                }
            }
            StartupScenario::RawBytes { mut bytes } => {
                bytes.truncate(MAX_PACKET_BYTES);
                StartupPacket {
                    bytes,
                    mutation_label: "raw_bytes",
                    expected: ExpectedOutcome::Unconstrained,
                    offending_field_index: None,
                }
            }
        }
    }
}

fn generated_param_name(idx: usize, seed: &[u8]) -> Vec<u8> {
    let mut name = format!("x_param_{idx}_").into_bytes();
    for &byte in seed.iter().take(MAX_FIELD_BYTES) {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.') {
            name.push(byte);
        }
    }
    name
}

fn generated_param_value(seed: &[u8]) -> Vec<u8> {
    seed.iter()
        .copied()
        .filter(|byte| *byte != 0 && byte.is_ascii())
        .take(MAX_FIELD_BYTES)
        .collect()
}

fn startup_packet_from_fields(fields: &[(Vec<u8>, Vec<u8>)], terminator: bool) -> Vec<u8> {
    let mut body = POSTGRES_PROTOCOL_VERSION_3_0.to_be_bytes().to_vec();
    for (name, value) in fields {
        body.extend_from_slice(name);
        body.push(0);
        body.extend_from_slice(value);
        body.push(0);
    }
    if terminator {
        body.push(0);
    }
    startup_packet_from_body(body)
}

fn startup_packet_from_parts(parts: &[&[u8]], terminator: bool) -> Vec<u8> {
    let mut body = POSTGRES_PROTOCOL_VERSION_3_0.to_be_bytes().to_vec();
    for part in parts {
        body.extend_from_slice(part);
        body.push(0);
    }
    if terminator {
        body.push(0);
    }
    startup_packet_from_body(body)
}

fn startup_packet_from_body(mut body: Vec<u8>) -> Vec<u8> {
    body.truncate(MAX_PACKET_BYTES.saturating_sub(4));
    let len = i32::try_from(body.len() + 4).unwrap_or(i32::MAX);
    let mut packet = len.to_be_bytes().to_vec();
    packet.extend_from_slice(&body);
    packet
}

fn declared_len(bytes: &[u8]) -> Option<i32> {
    (bytes.len() >= 4).then(|| i32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn error_kind(
    result: &Result<asupersync::database::postgres::FuzzStartupMessage, PgError>,
) -> &'static str {
    match result {
        Ok(_) => "ok",
        Err(PgError::Protocol(_)) => "protocol",
        Err(PgError::Io(_)) => "io",
        Err(PgError::AuthenticationFailed(_)) => "authentication",
        Err(PgError::Server { .. }) => "server",
        Err(PgError::Cancelled(_)) => "cancelled",
        Err(PgError::ConnectionClosed) => "connection_closed",
        Err(PgError::ColumnNotFound(_)) => "column_not_found",
        Err(PgError::TypeConversion { .. }) => "type_conversion",
        Err(PgError::InvalidUrl(_)) => "invalid_url",
        Err(PgError::TlsRequired) => "tls_required",
        Err(PgError::Tls(_)) => "tls",
        Err(PgError::TransactionFinished) => "transaction_finished",
        Err(PgError::UnsupportedAuth(_)) => "unsupported_auth",
        Err(PgError::IsolationLevelMismatch { .. }) => "isolation_level_mismatch",
    }
}

fn assert_protocol_rejection(bytes: &[u8], expected: &str) {
    let error =
        fuzz_parse_startup_message(bytes).expect_err("fixed startup-message canary should reject");

    match &error {
        PgError::Protocol(message) => assert_eq!(
            message, expected,
            "startup-message protocol payload changed"
        ),
        other => panic!("expected startup-message protocol error, got {other:?}"),
    }

    assert_eq!(
        error.to_string(),
        format!("PostgreSQL protocol error: {expected}"),
        "startup-message Display diagnostic changed"
    );
}

fn assert_fixed_startup_error_canaries() {
    assert_protocol_rejection(&[], "startup message too short");

    assert_protocol_rejection(
        &startup_packet_from_body((POSTGRES_PROTOCOL_VERSION_3_0 + 1).to_be_bytes().to_vec()),
        "unsupported startup protocol version: 196609",
    );

    assert_protocol_rejection(
        &startup_packet_from_fields(&[(b"user".to_vec(), b"testuser".to_vec())], false),
        "startup parameter list missing terminator",
    );

    assert_protocol_rejection(
        &startup_packet_from_parts(&[b"user", b"testuser", b"database"], false),
        "startup parameter \"database\" missing value",
    );

    assert_protocol_rejection(
        &startup_packet_from_fields(
            &[
                (b"user".to_vec(), b"alice".to_vec()),
                (b"user".to_vec(), b"admin".to_vec()),
            ],
            true,
        ),
        "duplicate startup parameter: user",
    );

    assert_protocol_rejection(
        &startup_packet_from_fields(&[(b"user".to_vec(), Vec::new())], true),
        "startup parameter user cannot be empty",
    );

    assert_protocol_rejection(
        &startup_packet_from_fields(&[(b"database".to_vec(), b"fuzz_db".to_vec())], true),
        "startup message missing required user parameter",
    );

    assert_protocol_rejection(
        &startup_packet_from_fields(&[(b"bad-name".to_vec(), b"value".to_vec())], true),
        "invalid startup parameter name: \"bad-name\"",
    );

    let mut body = POSTGRES_PROTOCOL_VERSION_3_0.to_be_bytes().to_vec();
    body.push(0);
    body.extend_from_slice(b"smuggled");
    assert_protocol_rejection(
        &startup_packet_from_body(body),
        "StartupMessage message has 8 trailing byte(s)",
    );
}

fuzz_target!(|data: &[u8]| {
    FIXED_CANARIES.get_or_init(assert_fixed_startup_error_canaries);

    let mut unstructured = Unstructured::new(data);
    let Ok(input) = StartupInput::arbitrary(&mut unstructured) else {
        return;
    };

    let packet = input.scenario.into_packet();
    let result = fuzz_parse_startup_message(&packet.bytes);
    let labels = StartupLabels {
        packet_len: packet.bytes.len(),
        declared_len: declared_len(&packet.bytes),
        param_count: result
            .as_ref()
            .map(|message| message.parameters.len())
            .unwrap_or(0),
        offending_field_index: packet.offending_field_index,
        mutation_label: packet.mutation_label,
        error_kind: error_kind(&result),
        accepted: result.is_ok(),
        authentication_reached: false,
    };
    black_box(labels);

    match packet.expected {
        ExpectedOutcome::Accept => {
            assert!(result.is_ok(), "valid startup packet rejected: {result:?}");
        }
        ExpectedOutcome::Reject => {
            assert!(result.is_err(), "malformed startup packet accepted");
        }
        ExpectedOutcome::Unconstrained => {}
    }
});
