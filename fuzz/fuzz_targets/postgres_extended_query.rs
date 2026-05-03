#![no_main]

//! Structure-aware fuzz target for PostgreSQL extended-query Parse/Bind frames.

use arbitrary::Arbitrary;
use asupersync::database::postgres::{
    Format, FuzzBindMessage, FuzzParseMessage, IsNull, PgError, ToSql, build_bind_msg,
    fuzz_build_parse_msg, fuzz_parse_bind_message, fuzz_parse_parse_message,
};
use libfuzzer_sys::fuzz_target;

const MAX_NAME_CHARS: usize = 64;
const MAX_SQL_CHARS: usize = 256;
const MAX_PARAMS: usize = 24;
const MAX_FORMAT_CODES: usize = 24;
const MAX_TEXT_BYTES: usize = 256;
const MAX_BINARY_BYTES: usize = 512;
const MAX_TRAILING_BYTES: usize = 16;

#[derive(Arbitrary, Debug, Clone)]
struct FuzzInput {
    parse: ParseScenario,
    bind: BindScenario,
}

#[derive(Arbitrary, Debug, Clone)]
struct ParseScenario {
    statement: String,
    sql: String,
    param_oids: Vec<u32>,
    declared_count: CountEncoding,
    mutation: FrameMutation,
}

#[derive(Arbitrary, Debug, Clone)]
struct BindScenario {
    portal: String,
    statement: String,
    params: Vec<CanonicalParam>,
    result_format: WireFormat,
    param_format_codes: Vec<FormatCodeSpec>,
    result_format_codes: Vec<FormatCodeSpec>,
    declared_param_format_count: CountEncoding,
    declared_value_count: CountEncoding,
    declared_result_count: CountEncoding,
    mutation: FrameMutation,
}

#[derive(Arbitrary, Debug, Clone, Copy)]
enum CountEncoding {
    Actual,
    Negative(u8),
    SmallerBy(u8),
    LargerBy(u8),
    Exact(u8),
}

impl CountEncoding {
    fn apply(self, actual: usize) -> i16 {
        match self {
            Self::Actual => actual.min(i16::MAX as usize) as i16,
            Self::Negative(seed) => -((i16::from(seed % 7)) + 1),
            Self::SmallerBy(delta) => actual.saturating_sub(usize::from((delta % 4) + 1)) as i16,
            Self::LargerBy(delta) => actual.saturating_add(usize::from((delta % 4) + 1)) as i16,
            Self::Exact(raw) => i16::from(raw % 32),
        }
    }
}

#[derive(Arbitrary, Debug, Clone)]
enum FrameMutation {
    None,
    Truncate(u16),
    Append(Vec<u8>),
    FlipByte { index: u16, mask: u8 },
    Length(LengthMutation),
}

#[derive(Arbitrary, Debug, Clone, Copy)]
enum LengthMutation {
    TooSmall(u8),
    SmallerBy(u8),
    LargerBy(u8),
    Zero,
    Negative,
    Huge(u16),
}

#[derive(Arbitrary, Debug, Clone, Copy)]
enum WireFormat {
    Text,
    Binary,
}

impl WireFormat {
    fn to_pg(self) -> Format {
        match self {
            Self::Text => Format::Text,
            Self::Binary => Format::Binary,
        }
    }
}

#[derive(Arbitrary, Debug, Clone)]
enum FormatCodeSpec {
    Text,
    Binary,
    Invalid(u16),
}

impl FormatCodeSpec {
    fn to_i16(&self) -> i16 {
        match self {
            Self::Text => 0,
            Self::Binary => 1,
            Self::Invalid(raw) => i16::from_be_bytes(raw.to_be_bytes()),
        }
    }
}

#[derive(Arbitrary, Debug, Clone)]
struct CanonicalParam {
    format: WireFormat,
    value: ParamValue,
}

impl CanonicalParam {
    fn sanitize(self) -> Self {
        Self {
            format: self.format,
            value: self.value.sanitize(),
        }
    }
}

#[derive(Arbitrary, Debug, Clone)]
enum ParamValue {
    Null,
    Bool(bool),
    Int32(i32),
    Int64(i64),
    Text(String),
    Binary(Vec<u8>),
    Error(String),
}

impl ParamValue {
    fn sanitize(self) -> Self {
        match self {
            Self::Null => Self::Null,
            Self::Bool(value) => Self::Bool(value),
            Self::Int32(value) => Self::Int32(value),
            Self::Int64(value) => Self::Int64(value),
            Self::Text(value) => Self::Text(value.chars().take(MAX_TEXT_BYTES).collect()),
            Self::Binary(bytes) => Self::Binary(bytes.into_iter().take(MAX_BINARY_BYTES).collect()),
            Self::Error(value) => Self::Error(value.chars().take(MAX_TEXT_BYTES).collect()),
        }
    }
}

struct FuzzParam<'a> {
    inner: &'a CanonicalParam,
}

impl FuzzParam<'_> {
    fn wire_bytes(&self) -> Option<Vec<u8>> {
        match &self.inner.value {
            ParamValue::Null => None,
            ParamValue::Bool(value) => match self.inner.format {
                WireFormat::Text => Some(if *value { b"t".to_vec() } else { b"f".to_vec() }),
                WireFormat::Binary => Some(vec![u8::from(*value)]),
            },
            ParamValue::Int32(value) => match self.inner.format {
                WireFormat::Text => Some(value.to_string().into_bytes()),
                WireFormat::Binary => Some(value.to_be_bytes().to_vec()),
            },
            ParamValue::Int64(value) => match self.inner.format {
                WireFormat::Text => Some(value.to_string().into_bytes()),
                WireFormat::Binary => Some(value.to_be_bytes().to_vec()),
            },
            ParamValue::Text(value) => Some(value.as_bytes().to_vec()),
            ParamValue::Binary(bytes) => Some(bytes.clone()),
            ParamValue::Error(_) => None,
        }
    }
}

impl ToSql for FuzzParam<'_> {
    fn to_sql(&self, buf: &mut Vec<u8>) -> Result<IsNull, PgError> {
        match &self.inner.value {
            ParamValue::Null => Ok(IsNull::Yes),
            ParamValue::Bool(_)
            | ParamValue::Int32(_)
            | ParamValue::Int64(_)
            | ParamValue::Text(_)
            | ParamValue::Binary(_) => {
                if let Some(bytes) = self.wire_bytes() {
                    buf.extend_from_slice(&bytes);
                }
                Ok(IsNull::No)
            }
            ParamValue::Error(message) => Err(PgError::Protocol(format!(
                "fuzz bind type mismatch: {message}"
            ))),
        }
    }

    fn type_oid(&self) -> u32 {
        0
    }

    fn format(&self) -> Format {
        self.inner.format.to_pg()
    }
}

fn normalize_cstring(input: &str, max_chars: usize) -> String {
    input
        .chars()
        .take(max_chars)
        .collect::<String>()
        .split('\0')
        .next()
        .unwrap_or_default()
        .to_string()
}

fn normalize_input(mut input: FuzzInput) -> FuzzInput {
    input.parse.statement = normalize_cstring(&input.parse.statement, MAX_NAME_CHARS);
    input.parse.sql = normalize_cstring(&input.parse.sql, MAX_SQL_CHARS);
    input.parse.param_oids.truncate(MAX_PARAMS);

    input.bind.portal = normalize_cstring(&input.bind.portal, MAX_NAME_CHARS);
    input.bind.statement = normalize_cstring(&input.bind.statement, MAX_NAME_CHARS);
    input.bind.params = input
        .bind
        .params
        .into_iter()
        .take(MAX_PARAMS)
        .map(CanonicalParam::sanitize)
        .collect();
    input.bind.param_format_codes.truncate(MAX_FORMAT_CODES);
    input.bind.result_format_codes.truncate(MAX_FORMAT_CODES);
    if let FrameMutation::Append(bytes) = &mut input.bind.mutation {
        bytes.truncate(MAX_TRAILING_BYTES);
    }
    if let FrameMutation::Append(bytes) = &mut input.parse.mutation {
        bytes.truncate(MAX_TRAILING_BYTES);
    }
    input
}

fn apply_length_mutation(frame: &mut [u8], mutation: LengthMutation) {
    let actual = frame.len().saturating_sub(1);
    let len = match mutation {
        LengthMutation::TooSmall(seed) => i32::from(seed % 4),
        LengthMutation::SmallerBy(delta) => {
            i32::try_from(actual.saturating_sub(usize::from((delta % 8) + 1))).unwrap_or(0)
        }
        LengthMutation::LargerBy(delta) => {
            i32::try_from(actual.saturating_add(usize::from((delta % 16) + 1))).unwrap_or(i32::MAX)
        }
        LengthMutation::Zero => 0,
        LengthMutation::Negative => -1,
        LengthMutation::Huge(raw) => 64 * 1024 * 1024 + i32::from((raw % 1024) + 1),
    };
    frame[1..5].copy_from_slice(&len.to_be_bytes());
}

fn apply_frame_mutation(mut frame: Vec<u8>, mutation: &FrameMutation) -> Vec<u8> {
    match mutation {
        FrameMutation::None => {}
        FrameMutation::Truncate(limit) => {
            let limit = usize::from(*limit) % (frame.len().saturating_add(1));
            frame.truncate(limit);
        }
        FrameMutation::Append(bytes) => frame.extend_from_slice(bytes),
        FrameMutation::FlipByte { index, mask } => {
            if !frame.is_empty() {
                let idx = usize::from(*index) % frame.len();
                frame[idx] ^= *mask;
            }
        }
        FrameMutation::Length(length_mutation) => {
            if frame.len() >= 5 {
                apply_length_mutation(&mut frame, *length_mutation);
            }
        }
    }
    frame
}

fn build_parse_frame(parse: &ParseScenario) -> Vec<u8> {
    let actual_count = parse.param_oids.len();
    let declared_count = parse.declared_count.apply(actual_count);

    if matches!(parse.declared_count, CountEncoding::Actual)
        && matches!(&parse.mutation, FrameMutation::None)
    {
        return fuzz_build_parse_msg(&parse.statement, &parse.sql, &parse.param_oids)
            .expect("canonical parse frame should build");
    }

    let mut body = Vec::new();
    body.extend_from_slice(parse.statement.as_bytes());
    body.push(0);
    body.extend_from_slice(parse.sql.as_bytes());
    body.push(0);
    body.extend_from_slice(&declared_count.to_be_bytes());
    for oid in &parse.param_oids {
        body.extend_from_slice(&(*oid as i32).to_be_bytes());
    }

    let mut frame = Vec::with_capacity(body.len() + 5);
    frame.push(b'P');
    frame.extend_from_slice(&(i32::try_from(body.len()).unwrap_or(i32::MAX) + 4).to_be_bytes());
    frame.extend_from_slice(&body);
    apply_frame_mutation(frame, &parse.mutation)
}

fn expected_production_param_formats(params: &[CanonicalParam]) -> Vec<i16> {
    let mut formats = Vec::with_capacity(params.len());
    let mut all_text = true;
    let mut all_same = true;
    let mut first = None;
    for param in params {
        let code = param.format.to_pg() as i16;
        all_text &= code == 0;
        if let Some(prev) = first {
            all_same &= prev == code;
        } else {
            first = Some(code);
        }
        formats.push(code);
    }

    if formats.is_empty() || all_text {
        Vec::new()
    } else if all_same {
        vec![first.expect("uniform format code exists")]
    } else {
        formats
    }
}

fn expected_values(params: &[CanonicalParam]) -> Vec<Option<Vec<u8>>> {
    params
        .iter()
        .map(|param| FuzzParam { inner: param }.wire_bytes())
        .collect()
}

fn build_manual_bind_frame(bind: &BindScenario) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(bind.portal.as_bytes());
    body.push(0);
    body.extend_from_slice(bind.statement.as_bytes());
    body.push(0);

    body.extend_from_slice(
        &bind
            .declared_param_format_count
            .apply(bind.param_format_codes.len())
            .to_be_bytes(),
    );
    for format in &bind.param_format_codes {
        body.extend_from_slice(&format.to_i16().to_be_bytes());
    }

    body.extend_from_slice(
        &bind
            .declared_value_count
            .apply(bind.params.len())
            .to_be_bytes(),
    );
    for param in &bind.params {
        match (FuzzParam { inner: param }).wire_bytes() {
            None => body.extend_from_slice(&(-1i32).to_be_bytes()),
            Some(bytes) => {
                body.extend_from_slice(&(bytes.len() as i32).to_be_bytes());
                body.extend_from_slice(&bytes);
            }
        }
    }

    body.extend_from_slice(
        &bind
            .declared_result_count
            .apply(bind.result_format_codes.len())
            .to_be_bytes(),
    );
    for format in &bind.result_format_codes {
        body.extend_from_slice(&format.to_i16().to_be_bytes());
    }

    let mut frame = Vec::with_capacity(body.len() + 5);
    frame.push(b'B');
    frame.extend_from_slice(&(i32::try_from(body.len()).unwrap_or(i32::MAX) + 4).to_be_bytes());
    frame.extend_from_slice(&body);
    apply_frame_mutation(frame, &bind.mutation)
}

fn fuzz_parse_round_trip(parse: &ParseScenario) {
    let frame = build_parse_frame(parse);
    let result = fuzz_parse_parse_message(&frame);

    if matches!(parse.declared_count, CountEncoding::Actual)
        && matches!(&parse.mutation, FrameMutation::None)
    {
        let expected = FuzzParseMessage {
            statement_name: parse.statement.clone(),
            sql: parse.sql.clone(),
            param_oids: parse.param_oids.clone(),
        };
        assert_eq!(
            result.expect("canonical Parse frame should decode"),
            expected
        );
    } else {
        let result_again = fuzz_parse_parse_message(&frame);
        assert_eq!(format!("{result:?}"), format!("{result_again:?}"));
    }
}

fn fuzz_bind_round_trip(bind: &BindScenario) {
    let owners: Vec<FuzzParam<'_>> = bind
        .params
        .iter()
        .map(|param| FuzzParam { inner: param })
        .collect();
    let params: Vec<&dyn ToSql> = owners.iter().map(|param| param as &dyn ToSql).collect();

    match build_bind_msg(
        &bind.portal,
        &bind.statement,
        &params,
        bind.result_format.to_pg(),
    ) {
        Ok(frame) => {
            assert!(
                bind.params
                    .iter()
                    .all(|param| !matches!(param.value, ParamValue::Error(_))),
                "bind builder succeeded despite injected parameter serialization error"
            );
            let parsed =
                fuzz_parse_bind_message(&frame).expect("canonical Bind frame should decode");
            let expected = FuzzBindMessage {
                portal: bind.portal.clone(),
                statement_name: bind.statement.clone(),
                param_format_codes: expected_production_param_formats(&bind.params),
                parameter_values: expected_values(&bind.params),
                result_format_codes: vec![bind.result_format.to_pg() as i16],
            };
            assert_eq!(parsed, expected);
        }
        Err(PgError::Protocol(message)) => {
            assert!(
                bind.params
                    .iter()
                    .any(|param| matches!(param.value, ParamValue::Error(_))),
                "unexpected bind protocol error: {message}"
            );
            assert!(
                message.contains("fuzz bind type mismatch"),
                "got: {message}"
            );
        }
        Err(other) => panic!("unexpected bind builder error: {other:?}"),
    }
}

fn fuzz_manual_bind_parser(bind: &BindScenario) {
    let frame = build_manual_bind_frame(bind);
    let result = fuzz_parse_bind_message(&frame);

    if matches!(bind.declared_param_format_count, CountEncoding::Actual)
        && matches!(bind.declared_value_count, CountEncoding::Actual)
        && matches!(bind.declared_result_count, CountEncoding::Actual)
        && matches!(&bind.mutation, FrameMutation::None)
    {
        let expected = FuzzBindMessage {
            portal: bind.portal.clone(),
            statement_name: bind.statement.clone(),
            param_format_codes: bind
                .param_format_codes
                .iter()
                .map(FormatCodeSpec::to_i16)
                .collect(),
            parameter_values: expected_values(&bind.params),
            result_format_codes: bind
                .result_format_codes
                .iter()
                .map(FormatCodeSpec::to_i16)
                .collect(),
        };
        assert_eq!(result.expect("manual Bind frame should decode"), expected);
    } else {
        let result_again = fuzz_parse_bind_message(&frame);
        assert_eq!(format!("{result:?}"), format!("{result_again:?}"));
    }
}

fuzz_target!(|input: FuzzInput| {
    let input = normalize_input(input);
    fuzz_parse_round_trip(&input.parse);
    fuzz_bind_round_trip(&input.bind);
    fuzz_manual_bind_parser(&input.bind);
});
