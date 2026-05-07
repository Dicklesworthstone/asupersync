#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use asupersync::database::mysql::{ToSql, fuzz_build_stmt_execute_packet};
use libfuzzer_sys::fuzz_target;

const COM_STMT_EXECUTE: u8 = 0x17;
const MAX_PARAMS: usize = 48;
const MAX_VAR_LEN: usize = 512;
const MYSQL_TYPE_TINY: u16 = 1;
const MYSQL_TYPE_LONG: u16 = 3;
const MYSQL_TYPE_DOUBLE: u16 = 5;
const MYSQL_TYPE_LONGLONG: u16 = 8;
const MYSQL_TYPE_BLOB: u16 = 252;
const MYSQL_TYPE_VAR_STRING: u16 = 253;
const UNSIGNED_FLAG: u16 = 0x80_00;

#[derive(Debug, Arbitrary)]
struct FuzzInput {
    statement_id: u32,
    params: Vec<ParamSpec>,
}

#[derive(Debug, Arbitrary)]
enum ParamSpec {
    MaybeBool(Option<bool>),
    MaybeI32(Option<i32>),
    MaybeU64(Option<u64>),
    MaybeF64(Option<f64>),
    MaybeText(Option<String>),
    MaybeBlob(Option<Vec<u8>>),
}

impl ParamSpec {
    fn clamp(&mut self) {
        match self {
            Self::MaybeText(Some(value)) => value.truncate(MAX_VAR_LEN),
            Self::MaybeBlob(Some(value)) => value.truncate(MAX_VAR_LEN),
            _ => {}
        }
    }

    fn as_tosql(&self) -> &dyn ToSql {
        match self {
            Self::MaybeBool(value) => value,
            Self::MaybeI32(value) => value,
            Self::MaybeU64(value) => value,
            Self::MaybeF64(value) => value,
            Self::MaybeText(value) => value,
            Self::MaybeBlob(value) => value,
        }
    }

    fn is_null(&self) -> bool {
        matches!(
            self,
            Self::MaybeBool(None)
                | Self::MaybeI32(None)
                | Self::MaybeU64(None)
                | Self::MaybeF64(None)
                | Self::MaybeText(None)
                | Self::MaybeBlob(None)
        )
    }

    fn expected_type_field(&self) -> u16 {
        match self {
            Self::MaybeBool(_) => MYSQL_TYPE_TINY | UNSIGNED_FLAG,
            Self::MaybeI32(_) => MYSQL_TYPE_LONG,
            Self::MaybeU64(_) => MYSQL_TYPE_LONGLONG | UNSIGNED_FLAG,
            Self::MaybeF64(_) => MYSQL_TYPE_DOUBLE,
            Self::MaybeText(_) => MYSQL_TYPE_VAR_STRING,
            Self::MaybeBlob(_) => MYSQL_TYPE_BLOB,
        }
    }

    fn expected_value_bytes(&self) -> Vec<u8> {
        match self {
            Self::MaybeBool(Some(value)) => vec![u8::from(*value)],
            Self::MaybeBool(None) => Vec::new(),
            Self::MaybeI32(Some(value)) => value.to_le_bytes().to_vec(),
            Self::MaybeI32(None) => Vec::new(),
            Self::MaybeU64(Some(value)) => value.to_le_bytes().to_vec(),
            Self::MaybeU64(None) => Vec::new(),
            Self::MaybeF64(Some(value)) => value.to_le_bytes().to_vec(),
            Self::MaybeF64(None) => Vec::new(),
            Self::MaybeText(Some(value)) => encode_lenenc_bytes(value.as_bytes()),
            Self::MaybeText(None) => Vec::new(),
            Self::MaybeBlob(Some(value)) => encode_lenenc_bytes(value),
            Self::MaybeBlob(None) => Vec::new(),
        }
    }
}

fuzz_target!(|data: &[u8]| {
    let Ok(mut input) = FuzzInput::arbitrary(&mut Unstructured::new(data)) else {
        return;
    };

    input.params.truncate(MAX_PARAMS);
    for param in &mut input.params {
        param.clamp();
    }

    let refs: Vec<&dyn ToSql> = input.params.iter().map(ParamSpec::as_tosql).collect();
    let packet = fuzz_build_stmt_execute_packet(input.statement_id, &refs)
        .expect("packet builder must encode");
    let repeat_packet = fuzz_build_stmt_execute_packet(input.statement_id, &refs)
        .expect("repeat encode must succeed");
    assert_eq!(
        packet, repeat_packet,
        "packet construction must be deterministic"
    );

    verify_packet(&packet, input.statement_id, &input.params);
});

fn verify_packet(packet: &[u8], statement_id: u32, params: &[ParamSpec]) {
    assert!(
        packet.len() >= 14,
        "packet must include header plus fixed execute payload"
    );
    assert_eq!(packet[3], 0, "fuzz helper pins the sequence byte to zero");

    let payload_len =
        usize::from(packet[0]) | (usize::from(packet[1]) << 8) | (usize::from(packet[2]) << 16);
    assert_eq!(
        payload_len,
        packet.len() - 4,
        "packet header length must match payload"
    );

    let payload = &packet[4..];
    assert_eq!(payload[0], COM_STMT_EXECUTE);
    assert_eq!(
        u32::from_le_bytes([payload[1], payload[2], payload[3], payload[4]]),
        statement_id
    );
    assert_eq!(
        payload[5], 0x00,
        "cursor flags default to CURSOR_TYPE_NO_CURSOR"
    );
    assert_eq!(
        u32::from_le_bytes([payload[6], payload[7], payload[8], payload[9]]),
        1,
        "iteration count must stay fixed at one"
    );

    if params.is_empty() {
        assert_eq!(
            payload.len(),
            10,
            "zero-parameter execute packets have no trailing parameter data"
        );
        return;
    }

    let null_bitmap_len = params.len().div_ceil(8);
    let types_start = 10 + null_bitmap_len + 1;
    let types_end = types_start + params.len() * 2;
    assert!(
        payload.len() >= types_end,
        "payload must contain null bitmap, new-params flag, and per-parameter type fields"
    );

    let null_bitmap = &payload[10..10 + null_bitmap_len];
    assert_eq!(null_bitmap, expected_null_bitmap(params));
    assert_eq!(
        payload[10 + null_bitmap_len],
        0x01,
        "new-params-bound flag must be present for every non-empty execute packet"
    );

    for (idx, param) in params.iter().enumerate() {
        let offset = types_start + idx * 2;
        let actual = u16::from_le_bytes([payload[offset], payload[offset + 1]]);
        assert_eq!(
            actual,
            param.expected_type_field(),
            "type field mismatch at parameter index {idx}"
        );
    }

    let expected_values = expected_value_stream(params);
    assert_eq!(
        &payload[types_end..],
        expected_values.as_slice(),
        "non-null values must be encoded in-order immediately after the type table"
    );
}

fn expected_null_bitmap(params: &[ParamSpec]) -> Vec<u8> {
    let mut bitmap = vec![0; params.len().div_ceil(8)];
    for (idx, param) in params.iter().enumerate() {
        if param.is_null() {
            bitmap[idx / 8] |= 1 << (idx % 8);
        }
    }
    bitmap
}

fn expected_value_stream(params: &[ParamSpec]) -> Vec<u8> {
    let mut values = Vec::new();
    for param in params {
        values.extend_from_slice(&param.expected_value_bytes());
    }
    values
}

fn encode_lenenc_bytes(bytes: &[u8]) -> Vec<u8> {
    let mut encoded = encode_lenenc_int(bytes.len());
    encoded.extend_from_slice(bytes);
    encoded
}

fn encode_lenenc_int(value: usize) -> Vec<u8> {
    if value < 251 {
        vec![u8::try_from(value).expect("length fits in u8")]
    } else if value <= usize::from(u16::MAX) {
        let len = u16::try_from(value).expect("length fits in u16");
        let mut out = vec![0xFC];
        out.extend_from_slice(&len.to_le_bytes());
        out
    } else if value <= 0x00FF_FFFF {
        let len = u32::try_from(value).expect("length fits in u24");
        vec![0xFD, len as u8, (len >> 8) as u8, (len >> 16) as u8]
    } else {
        let len = u64::try_from(value).expect("length fits in u64");
        let mut out = vec![0xFE];
        out.extend_from_slice(&len.to_le_bytes());
        out
    }
}
