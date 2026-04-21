#![no_main]

use arbitrary::Arbitrary;
use asupersync::database::postgres::{
    build_bind_msg, build_execute_msg, build_sync_msg, Format, IsNull, PgError, ToSql,
};
use libfuzzer_sys::fuzz_target;

const MAX_NAME_CHARS: usize = 64;
const MAX_PARAMS: usize = 32;
const MAX_TEXT_CHARS: usize = 128;
const MAX_BINARY_BYTES: usize = 512;
const EXCESSIVE_PARAM_COUNT: usize = i16::MAX as usize + 1;

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
enum ParamValue {
    Null,
    Bool(bool),
    Int32(i32),
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
            Self::Text(value) => Self::Text(value.chars().take(MAX_TEXT_CHARS).collect()),
            Self::Binary(bytes) => {
                Self::Binary(bytes.into_iter().take(MAX_BINARY_BYTES).collect())
            }
            Self::Error(message) => Self::Error(message.chars().take(MAX_TEXT_CHARS).collect()),
        }
    }
}

#[derive(Arbitrary, Debug, Clone)]
struct ParamInput {
    format: WireFormat,
    value: ParamValue,
}

impl ParamInput {
    fn sanitize(self) -> Self {
        Self {
            format: self.format,
            value: self.value.sanitize(),
        }
    }
}

#[derive(Arbitrary, Debug, Clone, Copy)]
enum BindCountMode {
    Normal,
    Excessive,
}

#[derive(Arbitrary, Debug, Clone)]
struct FuzzInput {
    portal: String,
    statement: String,
    result_format: WireFormat,
    max_rows: i32,
    bind_count_mode: BindCountMode,
    params: Vec<ParamInput>,
}

impl FuzzInput {
    fn sanitize(self) -> Self {
        Self {
            portal: self.portal.chars().take(MAX_NAME_CHARS).collect(),
            statement: self.statement.chars().take(MAX_NAME_CHARS).collect(),
            result_format: self.result_format,
            max_rows: self.max_rows,
            bind_count_mode: self.bind_count_mode,
            params: self
                .params
                .into_iter()
                .take(MAX_PARAMS)
                .map(ParamInput::sanitize)
                .collect(),
        }
    }
}

struct FuzzParam<'a> {
    inner: &'a ParamInput,
}

impl<'a> FuzzParam<'a> {
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

struct NullParam;

impl ToSql for NullParam {
    fn to_sql(&self, _buf: &mut Vec<u8>) -> Result<IsNull, PgError> {
        Ok(IsNull::Yes)
    }

    fn type_oid(&self) -> u32 {
        0
    }
}

fn normalized_cstring(input: &str) -> &[u8] {
    input.split('\0').next().unwrap_or_default().as_bytes()
}

fn expect_message_type(message: &[u8], expected: u8) -> &[u8] {
    assert!(message.len() >= 5, "postgres frontend message too short");
    assert_eq!(message[0], expected, "unexpected postgres frontend message type");
    let len = i32::from_be_bytes([message[1], message[2], message[3], message[4]]);
    assert!(len >= 4, "postgres frontend message length must include header");
    assert_eq!(usize::try_from(len).ok().map(|body| body + 1), Some(message.len()));
    &message[5..]
}

fn take_bytes<'a>(cursor: &mut &'a [u8], count: usize) -> &'a [u8] {
    assert!(cursor.len() >= count, "truncated postgres frontend message");
    let (head, tail) = cursor.split_at(count);
    *cursor = tail;
    head
}

fn take_i16(cursor: &mut &[u8]) -> i16 {
    let bytes = take_bytes(cursor, 2);
    i16::from_be_bytes([bytes[0], bytes[1]])
}

fn take_i32(cursor: &mut &[u8]) -> i32 {
    let bytes = take_bytes(cursor, 4);
    i32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
}

fn take_cstring<'a>(cursor: &mut &'a [u8]) -> &'a [u8] {
    let end = cursor
        .iter()
        .position(|byte| *byte == 0)
        .expect("postgres frontend message missing cstring terminator");
    let value = &cursor[..end];
    *cursor = &cursor[end + 1..];
    value
}

fn assert_bind_round_trip(message: &[u8], input: &FuzzInput) {
    let mut body = expect_message_type(message, b'B');
    assert_eq!(take_cstring(&mut body), normalized_cstring(&input.portal));
    assert_eq!(take_cstring(&mut body), normalized_cstring(&input.statement));

    let format_count = take_i16(&mut body);
    assert_eq!(usize::try_from(format_count).ok(), Some(input.params.len()));
    for param in &input.params {
        assert_eq!(take_i16(&mut body), param.format.to_pg() as i16);
    }

    let value_count = take_i16(&mut body);
    assert_eq!(usize::try_from(value_count).ok(), Some(input.params.len()));
    for param in &input.params {
        let fuzz_param = FuzzParam { inner: param };
        match fuzz_param.wire_bytes() {
            Some(expected) => {
                let len = take_i32(&mut body);
                assert_eq!(usize::try_from(len).ok(), Some(expected.len()));
                assert_eq!(take_bytes(&mut body, expected.len()), expected.as_slice());
            }
            None => assert_eq!(take_i32(&mut body), -1),
        }
    }

    assert_eq!(take_i16(&mut body), 1);
    assert_eq!(take_i16(&mut body), input.result_format.to_pg() as i16);
    assert!(body.is_empty(), "bind message carried unexpected trailing bytes");
}

fn assert_execute_round_trip(message: &[u8], input: &FuzzInput) {
    let mut body = expect_message_type(message, b'E');
    assert_eq!(take_cstring(&mut body), normalized_cstring(&input.portal));
    assert_eq!(take_i32(&mut body), input.max_rows);
    assert!(body.is_empty(), "execute message carried unexpected trailing bytes");
}

fn assert_sync_round_trip(message: &[u8]) {
    let body = expect_message_type(message, b'S');
    assert!(body.is_empty(), "sync message carried unexpected trailing bytes");
}

fn assert_stream_boundaries(messages: &[&[u8]]) {
    let mut stream = Vec::new();
    for message in messages {
        stream.extend_from_slice(message);
    }

    let mut cursor = stream.as_slice();
    for message in messages {
        assert!(cursor.len() >= 5, "concatenated postgres stream truncated");
        let len = i32::from_be_bytes([cursor[1], cursor[2], cursor[3], cursor[4]]);
        assert!(len >= 4, "postgres frontend length prefix underflow");
        let frame_len = usize::try_from(len).expect("non-negative postgres length") + 1;
        assert!(
            cursor.len() >= frame_len,
            "concatenated postgres stream truncated mid-frame"
        );
        assert_eq!(&cursor[..frame_len], *message);
        cursor = &cursor[frame_len..];
    }
    assert!(cursor.is_empty(), "concatenated postgres stream has leftover bytes");
}

fn fuzz_bind_execute_sync(mut input: FuzzInput) {
    input = input.sanitize();

    let execute = build_execute_msg(&input.portal, input.max_rows).expect("execute builder failed");
    let sync = build_sync_msg().expect("sync builder failed");
    assert_execute_round_trip(&execute, &input);
    assert_sync_round_trip(&sync);

    if matches!(input.bind_count_mode, BindCountMode::Excessive) {
        let null_param = NullParam;
        let params = vec![&null_param as &dyn ToSql; EXCESSIVE_PARAM_COUNT];
        match build_bind_msg(
            &input.portal,
            &input.statement,
            &params,
            input.result_format.to_pg(),
        ) {
            Err(PgError::Protocol(message)) => {
                assert!(
                    message.contains("too many parameters"),
                    "unexpected bind overflow error"
                );
            }
            other => panic!("expected too-many-parameters error, got {other:?}"),
        }
        assert_stream_boundaries(&[&execute, &sync]);
        return;
    }

    let owners: Vec<FuzzParam<'_>> = input
        .params
        .iter()
        .map(|param| FuzzParam { inner: param })
        .collect();
    let params: Vec<&dyn ToSql> = owners.iter().map(|param| param as &dyn ToSql).collect();

    match build_bind_msg(&input.portal, &input.statement, &params, input.result_format.to_pg()) {
        Ok(bind) => {
            assert!(
                input
                    .params
                    .iter()
                    .all(|param| !matches!(param.value, ParamValue::Error(_))),
                "bind builder succeeded despite injected param error"
            );
            assert_bind_round_trip(&bind, &input);
            assert_stream_boundaries(&[&bind, &execute, &sync]);
        }
        Err(PgError::Protocol(message)) => {
            assert!(
                input
                    .params
                    .iter()
                    .any(|param| matches!(param.value, ParamValue::Error(_))),
                "bind builder returned protocol error without injected error param: {message}"
            );
            assert!(
                message.contains("fuzz bind type mismatch"),
                "unexpected bind error: {message}"
            );
            assert_stream_boundaries(&[&execute, &sync]);
        }
        Err(other) => panic!("unexpected bind builder error: {other:?}"),
    }
}

fuzz_target!(|input: FuzzInput| {
    fuzz_bind_execute_sync(input);
});
