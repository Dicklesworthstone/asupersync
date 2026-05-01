#![no_main]

use arbitrary::Arbitrary;
use asupersync::database::postgres::{
    FuzzBindMessage, PgError, fuzz_parse_bind_message, fuzz_parse_parameter_description, oid,
};
use libfuzzer_sys::fuzz_target;

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
    FormatCountMismatch,
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
            Scenario::BinaryClientTextOid => vec![1; params.len()],
            Scenario::FormatCountMismatch => {
                let count = if params.len() == 1 {
                    2
                } else {
                    params.len() + 1
                };
                vec![1; count.min(MAX_PARAMS + 1)]
            }
            _ => params.iter().map(|param| param.format.to_i16()).collect(),
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
            .map(|format| format.to_i16())
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
    fn to_i16(self) -> i16 {
        match self {
            Self::Text => 0,
            Self::Binary => 1,
            Self::Other(code) => code,
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

    match case.scenario {
        Scenario::BinaryClientTextOid => exercise_binary_text_oid_case(&case, &frame),
        Scenario::FormatCountMismatch => exercise_format_count_mismatch(&frame),
        Scenario::MessageLengthOverflow | Scenario::ValueLengthOverflow => {}
        Scenario::NullMarkers => exercise_null_marker_case(&case, &frame),
        Scenario::GeneralValid => {
            assert_parameter_description_round_trip(&case.oids);
            assert_eq!(
                fuzz_parse_bind_message(&frame).expect("generated Bind should decode"),
                expected_valid_bind(&case)
            );
        }
    }
}

fuzz_target!(|input: FuzzInput| {
    exercise_case(input);
});
