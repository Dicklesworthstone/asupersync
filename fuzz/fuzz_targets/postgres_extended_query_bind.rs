#![no_main]

use arbitrary::Arbitrary;
use asupersync::database::postgres::{
    FuzzBindMessage, PgError, fuzz_parse_bind_message, fuzz_parse_parameter_description, oid,
};
use libfuzzer_sys::fuzz_target;
use std::hint::black_box;

const MAX_NAME_BYTES: usize = 48;
const MAX_PARAMS: usize = 16;
const MAX_VALUE_BYTES: usize = 128;
const MAX_RESULT_FORMATS: usize = 8;

#[derive(Arbitrary, Debug, Clone)]
struct FuzzInput {
    scenario: Scenario,
    portal: Vec<u8>,
    statement: Vec<u8>,
    params: Vec<ParamInput>,
    result_formats: Vec<FormatCode>,
    message_length: MessageLength,
    value_length_overflow: ValueLengthOverflow,
}

#[derive(Arbitrary, Debug, Clone, Copy, PartialEq, Eq)]
enum Scenario {
    BinaryClientTextOid,
    DefaultTextFormatCountZero,
    GlobalBinaryFormatCountOne,
    PerParameterMixedFormats,
    FormatCountMismatch,
    InvalidFormatCode,
    MessageLengthOverflow,
    ValueLengthOverflow,
    NullMarkers,
    GeneralValid,
}

#[derive(Arbitrary, Debug, Clone)]
struct ParamInput {
    oid: OidInput,
    format: FormatCode,
    value: Vec<u8>,
    null: bool,
}

#[derive(Arbitrary, Debug, Clone, Copy)]
enum OidInput {
    Text,
    Int4,
    Bytea,
    Bool,
    Unknown(u32),
}

#[derive(Arbitrary, Debug, Clone, Copy)]
enum FormatCode {
    Text,
    Binary,
    Other(i16),
}

#[derive(Arbitrary, Debug, Clone, Copy)]
enum MessageLength {
    Actual,
    OneByteShort,
    OneByteLong,
    MaxPositive,
    MinNegative,
    MinusOne,
}

#[derive(Arbitrary, Debug, Clone, Copy)]
enum ValueLengthOverflow {
    MaxPositive,
    MinNegative,
    DeclaredTooLong(u16),
}

#[derive(Debug)]
struct BindCase {
    scenario: Scenario,
    portal: String,
    statement: String,
    oids: Vec<u32>,
    format_codes: Vec<i16>,
    values: Vec<EncodedValue>,
    result_formats: Vec<i16>,
    message_length: MessageLength,
}

#[derive(Debug)]
struct BindLabels {
    corpus_label: &'static str,
    parameter_count: usize,
    format_code_count: usize,
    per_parameter_code_vector: Vec<i16>,
    payload_lengths: Vec<i32>,
    offending_index: Option<usize>,
    parser_outcome: &'static str,
    error_kind: &'static str,
    round_trip_verdict: &'static str,
}

impl BindLabels {
    fn expose(self) {
        black_box((
            self.corpus_label,
            self.parameter_count,
            self.format_code_count,
            self.per_parameter_code_vector,
            self.payload_lengths,
            self.offending_index,
            self.parser_outcome,
            self.error_kind,
            self.round_trip_verdict,
        ));
    }
}

#[derive(Debug)]
enum EncodedValue {
    Null,
    Bytes(Vec<u8>),
    LenOnly(i32),
}

impl FuzzInput {
    fn into_case(self) -> BindCase {
        let scenario = self.scenario;
        let mut params: Vec<ParamInput> = self.params.into_iter().take(MAX_PARAMS).collect();
        if params.is_empty() {
            params.push(ParamInput {
                oid: OidInput::Text,
                format: FormatCode::Binary,
                value: b"seed".to_vec(),
                null: false,
            });
        }
        if scenario == Scenario::NullMarkers && params.len() == 1 {
            params.push(ParamInput {
                oid: OidInput::Text,
                format: FormatCode::Text,
                value: b"after-null".to_vec(),
                null: false,
            });
        }

        let oids = match scenario {
            Scenario::BinaryClientTextOid => vec![oid::TEXT; params.len()],
            _ => params.iter().map(|param| param.oid.to_oid()).collect(),
        };
        let format_codes = match scenario {
            Scenario::DefaultTextFormatCountZero => Vec::new(),
            Scenario::GlobalBinaryFormatCountOne => vec![1],
            Scenario::PerParameterMixedFormats => {
                (0..params.len()).map(|index| (index % 2) as i16).collect()
            }
            Scenario::BinaryClientTextOid => vec![1; params.len()],
            Scenario::FormatCountMismatch => {
                let count = if params.len() == 1 {
                    2
                } else {
                    params.len() + 1
                };
                vec![1; count.min(MAX_PARAMS + 1)]
            }
            Scenario::InvalidFormatCode => {
                let mut codes = params
                    .iter()
                    .enumerate()
                    .map(|(index, param)| param.format.to_valid_i16(index))
                    .collect::<Vec<_>>();
                let offending_index = codes.len() / 2;
                codes[offending_index] = params[offending_index].format.to_invalid_i16();
                codes
            }
            _ => params
                .iter()
                .enumerate()
                .map(|(index, param)| param.format.to_valid_i16(index))
                .collect(),
        };
        let values = params
            .into_iter()
            .enumerate()
            .map(|(index, param)| {
                if scenario == Scenario::NullMarkers && index % 2 == 0 {
                    EncodedValue::Null
                } else if scenario == Scenario::ValueLengthOverflow && index == 0 {
                    EncodedValue::LenOnly(self.value_length_overflow.to_i32(param.value.len()))
                } else if param.null {
                    EncodedValue::Null
                } else {
                    EncodedValue::Bytes(param.value.into_iter().take(MAX_VALUE_BYTES).collect())
                }
            })
            .collect();
        let result_formats = self
            .result_formats
            .into_iter()
            .take(MAX_RESULT_FORMATS)
            .enumerate()
            .map(|(index, format)| format.to_valid_i16(index))
            .collect();

        BindCase {
            scenario,
            portal: sanitize_cstring(self.portal),
            statement: sanitize_cstring(self.statement),
            oids,
            format_codes,
            values,
            result_formats,
            message_length: self.message_length,
        }
    }
}

impl OidInput {
    fn to_oid(self) -> u32 {
        match self {
            Self::Text => oid::TEXT,
            Self::Int4 => oid::INT4,
            Self::Bytea => oid::BYTEA,
            Self::Bool => oid::BOOL,
            Self::Unknown(oid) => oid,
        }
    }
}

impl FormatCode {
    fn to_valid_i16(self, index: usize) -> i16 {
        match self {
            Self::Text => 0,
            Self::Binary => 1,
            Self::Other(_) => (index % 2) as i16,
        }
    }

    fn to_invalid_i16(self) -> i16 {
        match self {
            Self::Other(code) if code != 0 && code != 1 => code,
            Self::Text | Self::Binary | Self::Other(_) => 2,
        }
    }
}

impl ValueLengthOverflow {
    fn to_i32(self, actual_len: usize) -> i32 {
        match self {
            Self::MaxPositive => i32::MAX,
            Self::MinNegative => i32::MIN,
            Self::DeclaredTooLong(extra) => {
                let declared = actual_len.saturating_add(extra as usize).saturating_add(1);
                i32::try_from(declared).unwrap_or(i32::MAX)
            }
        }
    }
}

fn sanitize_cstring(bytes: Vec<u8>) -> String {
    bytes
        .into_iter()
        .filter(|&byte| byte != 0)
        .take(MAX_NAME_BYTES)
        .map(|byte| char::from(1 + (byte % 0x7f)))
        .collect()
}

fn parameter_description_body(oids: &[u32]) -> Vec<u8> {
    let mut body = Vec::with_capacity(2 + oids.len() * 4);
    body.extend_from_slice(&(oids.len() as i16).to_be_bytes());
    for &oid in oids {
        body.extend_from_slice(&(oid as i32).to_be_bytes());
    }
    body
}

fn build_bind_frame(case: &BindCase) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(case.portal.as_bytes());
    body.push(0);
    body.extend_from_slice(case.statement.as_bytes());
    body.push(0);

    body.extend_from_slice(&(case.format_codes.len() as i16).to_be_bytes());
    for &format in &case.format_codes {
        body.extend_from_slice(&format.to_be_bytes());
    }

    body.extend_from_slice(&(case.values.len() as i16).to_be_bytes());
    for value in &case.values {
        match value {
            EncodedValue::Null => body.extend_from_slice(&(-1i32).to_be_bytes()),
            EncodedValue::Bytes(bytes) => {
                body.extend_from_slice(&(bytes.len() as i32).to_be_bytes());
                body.extend_from_slice(bytes);
            }
            EncodedValue::LenOnly(len) => body.extend_from_slice(&len.to_be_bytes()),
        }
    }

    body.extend_from_slice(&(case.result_formats.len() as i16).to_be_bytes());
    for &format in &case.result_formats {
        body.extend_from_slice(&format.to_be_bytes());
    }

    let actual_len = body.len() + 4;
    let len = match case.scenario {
        Scenario::MessageLengthOverflow => case.message_length.to_i32(actual_len),
        _ => MessageLength::Actual.to_i32(actual_len),
    };

    let mut frame = Vec::with_capacity(1 + 4 + body.len());
    frame.push(b'B');
    frame.extend_from_slice(&len.to_be_bytes());
    frame.extend_from_slice(&body);
    frame
}

impl MessageLength {
    fn to_i32(self, actual_len: usize) -> i32 {
        let actual = i32::try_from(actual_len).unwrap_or(i32::MAX);
        match self {
            Self::Actual => actual,
            Self::OneByteShort => actual.saturating_sub(1),
            Self::OneByteLong => actual.saturating_add(1),
            Self::MaxPositive => i32::MAX,
            Self::MinNegative => i32::MIN,
            Self::MinusOne => -1,
        }
    }
}

fn assert_parameter_description_round_trip(oids: &[u32]) {
    let parsed = fuzz_parse_parameter_description(&parameter_description_body(oids))
        .expect("generated ParameterDescription should decode");
    assert_eq!(parsed, oids);
}

fn assert_stable_bind_parse(frame: &[u8]) {
    let first = fuzz_parse_bind_message(frame);
    let second = fuzz_parse_bind_message(frame);
    assert_eq!(format!("{first:?}"), format!("{second:?}"));
}

fn expected_values(values: &[EncodedValue]) -> Vec<Option<Vec<u8>>> {
    values
        .iter()
        .map(|value| match value {
            EncodedValue::Null => None,
            EncodedValue::Bytes(bytes) => Some(bytes.clone()),
            EncodedValue::LenOnly(_) => None,
        })
        .collect()
}

fn expected_valid_bind(case: &BindCase) -> FuzzBindMessage {
    FuzzBindMessage {
        portal: case.portal.clone(),
        statement_name: case.statement.clone(),
        param_format_codes: case.format_codes.clone(),
        parameter_values: expected_values(&case.values),
        result_format_codes: case.result_formats.clone(),
    }
}

fn bind_labels(case: &BindCase, result: &Result<FuzzBindMessage, PgError>) -> BindLabels {
    BindLabels {
        corpus_label: case.scenario.label(),
        parameter_count: case.values.len(),
        format_code_count: case.format_codes.len(),
        per_parameter_code_vector: case.format_codes.clone(),
        payload_lengths: case
            .values
            .iter()
            .map(|value| match value {
                EncodedValue::Null => -1,
                EncodedValue::Bytes(bytes) => i32::try_from(bytes.len()).unwrap_or(i32::MAX),
                EncodedValue::LenOnly(len) => *len,
            })
            .collect(),
        offending_index: case
            .format_codes
            .iter()
            .position(|code| *code != 0 && *code != 1),
        parser_outcome: if result.is_ok() { "ok" } else { "err" },
        error_kind: match result {
            Ok(_) => "none",
            Err(PgError::Protocol(message)) if message.contains("format code") => "format_code",
            Err(PgError::Protocol(message)) if message.contains("format count") => "format_count",
            Err(PgError::Protocol(message)) if message.contains("length") => "length",
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
            Err(PgError::IsolationLevelMismatch { .. }) => "isolation_mismatch",
        },
        round_trip_verdict: match result {
            Ok(parsed) if parsed == &expected_valid_bind(case) => "match",
            Ok(_) => "mismatch",
            Err(_) => "not_applicable",
        },
    }
}

impl Scenario {
    fn label(self) -> &'static str {
        match self {
            Self::BinaryClientTextOid => "binary-client-text-oid",
            Self::DefaultTextFormatCountZero => "default-text-format-count-zero",
            Self::GlobalBinaryFormatCountOne => "global-binary-format-count-one",
            Self::PerParameterMixedFormats => "per-parameter-mixed-formats",
            Self::FormatCountMismatch => "format-count-mismatch",
            Self::InvalidFormatCode => "invalid-format-code",
            Self::MessageLengthOverflow => "message-length-overflow",
            Self::ValueLengthOverflow => "value-length-overflow",
            Self::NullMarkers => "null-markers",
            Self::GeneralValid => "general-valid",
        }
    }
}

fn exercise_binary_text_oid_case(case: &BindCase, frame: &[u8]) {
    assert!(case.oids.iter().all(|&oid| oid == oid::TEXT));
    assert!(case.format_codes.iter().all(|&format| format == 1));
    assert_parameter_description_round_trip(&case.oids);
    assert_eq!(
        fuzz_parse_bind_message(frame).expect("binary Bind with TEXT OIDs should decode"),
        expected_valid_bind(case)
    );
}

fn exercise_format_count_mismatch(frame: &[u8]) {
    match fuzz_parse_bind_message(frame) {
        Err(PgError::Protocol(message)) => {
            assert!(
                message.contains("bind format count"),
                "unexpected mismatch error: {message}"
            );
        }
        other => panic!("format-count mismatch should fail cleanly, got {other:?}"),
    }
}

fn exercise_invalid_format_code(frame: &[u8]) {
    match fuzz_parse_bind_message(frame) {
        Err(PgError::Protocol(message)) => {
            assert!(
                message.contains("format code"),
                "unexpected invalid-format error: {message}"
            );
        }
        other => panic!("invalid format code should fail cleanly, got {other:?}"),
    }
}

fn exercise_null_marker_case(case: &BindCase, frame: &[u8]) {
    assert_parameter_description_round_trip(&case.oids);
    let parsed = fuzz_parse_bind_message(frame).expect("Bind with NULL markers should decode");
    assert_eq!(parsed, expected_valid_bind(case));
    assert!(
        parsed.parameter_values.iter().any(Option::is_none),
        "NULL marker (-1) must decode to None"
    );
}

fn exercise_case(input: FuzzInput) {
    let case = input.into_case();
    let frame = build_bind_frame(&case);
    assert_stable_bind_parse(&frame);
    let parse_result = fuzz_parse_bind_message(&frame);
    bind_labels(&case, &parse_result).expose();

    match case.scenario {
        Scenario::BinaryClientTextOid => exercise_binary_text_oid_case(&case, &frame),
        Scenario::DefaultTextFormatCountZero
        | Scenario::GlobalBinaryFormatCountOne
        | Scenario::PerParameterMixedFormats
        | Scenario::GeneralValid => {
            assert_parameter_description_round_trip(&case.oids);
            assert_eq!(
                parse_result.expect("generated Bind should decode"),
                expected_valid_bind(&case)
            );
        }
        Scenario::FormatCountMismatch => exercise_format_count_mismatch(&frame),
        Scenario::InvalidFormatCode => exercise_invalid_format_code(&frame),
        Scenario::MessageLengthOverflow | Scenario::ValueLengthOverflow => {}
        Scenario::NullMarkers => exercise_null_marker_case(&case, &frame),
    }
}

fuzz_target!(|input: FuzzInput| {
    exercise_case(input);
});
