#![no_main]

use arbitrary::Arbitrary;
use asupersync::messaging::redis::{RedisError, RedisProtocolLimits, RespValue};
use libfuzzer_sys::fuzz_target;
use std::sync::OnceLock;

const MAX_WIRE_LEN: usize = 16 * 1024;
const MAX_PAYLOAD_LEN: usize = 256;
const MAX_PAIRS: usize = 16;
const MAX_DEPTH: usize = 48;

static FIXED_ATTRIBUTE_CANARIES: OnceLock<()> = OnceLock::new();

#[derive(Debug, Arbitrary)]
struct AttributeCase {
    limits: FuzzLimits,
    scenario: AttributeScenario,
}

#[derive(Debug, Arbitrary)]
struct FuzzLimits {
    max_array_len: u8,
    max_nesting_depth: u8,
    max_bulk_string_len: u16,
}

#[derive(Debug, Arbitrary)]
enum AttributeScenario {
    EmptyAttributeMap,
    DeeplyNestedAttributes { depth: u8, leaf: Vec<u8> },
    AttributeBeforeNestedAggregate { aggregate: AggregateShape },
    NestedAggregateContainsAttribute { aggregate: AggregateShape },
    MalformedAttributePrefix { prefix: LengthPrefix, tail: Vec<u8> },
    RawAttributeBytes { data: Vec<u8> },
}

#[derive(Debug, Arbitrary)]
enum AggregateShape {
    EmptyArray,
    ArrayWithBulk { payload: Vec<u8> },
    ArrayWithMap { key: Vec<u8>, value: Vec<u8> },
    MapWithArray { key: Vec<u8>, value: Vec<u8> },
    SetWithBulk { payload: Vec<u8> },
}

#[derive(Debug, Arbitrary)]
enum LengthPrefix {
    Negative(i16),
    Overflow(Vec<u8>),
    NonDigits(Vec<u8>),
    MissingCrlf(Vec<u8>),
    TruncatedPair,
}

fuzz_target!(|case: AttributeCase| {
    let limits = case.limits.normalized();

    FIXED_ATTRIBUTE_CANARIES.get_or_init(assert_attribute_canaries);
    assert_empty_attribute_map(&limits);
    parse_without_harness_panic(&deep_attribute_wire(24, b"seed"), &limits);
    parse_adjacent_values_without_harness_panic(
        &attribute_before_nested_aggregate(AggregateShape::ArrayWithBulk {
            payload: b"seed".to_vec(),
        }),
        &limits,
    );
    parse_without_harness_panic(
        &nested_aggregate_contains_attribute(AggregateShape::MapWithArray {
            key: b"meta".to_vec(),
            value: b"value".to_vec(),
        }),
        &limits,
    );

    fuzz_attribute_parse(case.scenario, &limits);
});

fn assert_attribute_canaries() {
    let limits = canary_limits();

    assert_exact_decode(
        b"|1\r\n+ttl\r\n:7\r\n",
        RespValue::Attribute(vec![(
            RespValue::SimpleString("ttl".into()),
            RespValue::Integer(7),
        )]),
        &limits,
    );

    assert_exact_decode(
        &deep_attribute_wire(3, b"seed"),
        RespValue::Attribute(vec![(
            RespValue::BulkString(Some(b"a0".to_vec())),
            RespValue::Attribute(vec![(
                RespValue::BulkString(Some(b"a1".to_vec())),
                RespValue::Attribute(vec![(
                    RespValue::BulkString(Some(b"a2".to_vec())),
                    RespValue::BulkString(Some(b"seed".to_vec())),
                )]),
            )]),
        )]),
        &limits,
    );

    let adjacent = attribute_before_nested_aggregate(AggregateShape::EmptyArray);
    let (decoded, used) = decode_one(&adjacent, &limits);
    assert_eq!(
        decoded,
        RespValue::Attribute(vec![(
            RespValue::SimpleString("meta".into()),
            RespValue::Integer(1),
        )])
    );
    assert!(used < adjacent.len(), "attribute must leave adjacent value");
    assert_exact_decode(&adjacent[used..], RespValue::Array(Some(vec![])), &limits);

    assert_exact_decode(
        &nested_aggregate_contains_attribute(AggregateShape::ArrayWithBulk {
            payload: b"payload".to_vec(),
        }),
        RespValue::Array(Some(vec![
            RespValue::Attribute(vec![(
                RespValue::SimpleString("meta".into()),
                RespValue::SimpleString("value".into()),
            )]),
            RespValue::Array(Some(vec![RespValue::BulkString(Some(b"payload".to_vec()))])),
        ])),
        &limits,
    );

    assert_no_complete_decode(
        &malformed_attribute_prefix(LengthPrefix::TruncatedPair, b"key".to_vec()),
        &limits,
    );

    assert_protocol_message(b"|-1\r\n", "invalid aggregate length: -1", &limits);
    assert_protocol_message(
        b"|17\r\n",
        "aggregate length 17 exceeds maximum 16",
        &limits,
    );
    assert_protocol_message(b"|abc\r\n", "invalid integer byte: 0x61", &limits);
    assert_protocol_message(
        b"|?\r\n+meta\r\n.\r\n",
        "RESP3 streamed aggregate not supported for type byte 0x7c",
        &limits,
    );
    assert_protocol_message(
        b"|1\r\n+key\r\n.\r\n",
        "unknown RESP type byte: 0x2e",
        &limits,
    );
}

fn fuzz_attribute_parse(scenario: AttributeScenario, limits: &RedisProtocolLimits) {
    let wire = match scenario {
        AttributeScenario::EmptyAttributeMap => b"|0\r\n".to_vec(),
        AttributeScenario::DeeplyNestedAttributes { depth, leaf } => {
            deep_attribute_wire(usize::from(depth).min(MAX_DEPTH), &bounded_payload(leaf))
        }
        AttributeScenario::AttributeBeforeNestedAggregate { aggregate } => {
            attribute_before_nested_aggregate(aggregate)
        }
        AttributeScenario::NestedAggregateContainsAttribute { aggregate } => {
            nested_aggregate_contains_attribute(aggregate)
        }
        AttributeScenario::MalformedAttributePrefix { prefix, tail } => {
            malformed_attribute_prefix(prefix, bounded_payload(tail))
        }
        AttributeScenario::RawAttributeBytes { data } => {
            let mut wire = Vec::with_capacity(data.len().saturating_add(1).min(MAX_WIRE_LEN));
            wire.push(b'|');
            wire.extend_from_slice(&bounded_wire(data));
            wire
        }
    };

    parse_adjacent_values_without_harness_panic(&wire, limits);
}

fn assert_empty_attribute_map(limits: &RedisProtocolLimits) {
    let decoded = RespValue::try_decode_with_limits(b"|0\r\n", limits)
        .expect("empty RESP3 attribute map should parse");
    let Some((RespValue::Attribute(pairs), used)) = decoded else {
        panic!("empty RESP3 attribute map must decode as Attribute");
    };
    assert!(pairs.is_empty());
    assert_eq!(used, b"|0\r\n".len());
}

fn assert_exact_decode(wire: &[u8], expected: RespValue, limits: &RedisProtocolLimits) {
    let (decoded, used) = decode_one(wire, limits);
    assert_eq!(decoded, expected);
    assert_eq!(used, wire.len(), "canary must consume full RESP3 frame");
}

fn decode_one(wire: &[u8], limits: &RedisProtocolLimits) -> (RespValue, usize) {
    RespValue::try_decode_with_limits(wire, limits)
        .expect("RESP3 canary should not produce a protocol error")
        .expect("RESP3 canary should decode a complete value")
}

fn assert_no_complete_decode(wire: &[u8], limits: &RedisProtocolLimits) {
    match RespValue::try_decode_with_limits(wire, limits) {
        Ok(None) => {}
        Err(error) => observe_decode_error(&error, "malformed RESP3 attribute canary"),
        Ok(Some((decoded, used))) => {
            panic!("malformed RESP3 attribute decoded as {decoded:?} using {used} bytes");
        }
    }
}

fn assert_protocol_message(wire: &[u8], expected_message: &str, limits: &RedisProtocolLimits) {
    match RespValue::try_decode_with_limits(wire, limits) {
        Err(RedisError::Protocol(message)) => {
            assert_eq!(message, expected_message);
            assert_eq!(
                RedisError::Protocol(message).to_string(),
                format!("Redis protocol error: {expected_message}")
            );
        }
        Err(error) => panic!("expected RESP3 attribute protocol error, got {error:?}"),
        Ok(decoded) => {
            panic!("expected RESP3 attribute protocol error {expected_message:?}, got {decoded:?}");
        }
    }
}

fn parse_adjacent_values_without_harness_panic(wire: &[u8], limits: &RedisProtocolLimits) {
    let wire = bounded_wire_ref(wire);
    let Ok(Some((_, used))) = RespValue::try_decode_with_limits(wire, limits) else {
        return;
    };
    if used < wire.len() {
        parse_without_harness_panic(&wire[used..], limits);
    }
}

fn parse_without_harness_panic(wire: &[u8], limits: &RedisProtocolLimits) {
    observe_decode_result(bounded_wire_ref(wire), limits, "RESP3 attribute fuzz input");
}

fn observe_decode_result(wire: &[u8], limits: &RedisProtocolLimits, context: &str) {
    match RespValue::try_decode_with_limits(wire, limits) {
        Ok(Some((decoded, used))) => {
            assert_ne!(used, 0, "{context}: successful decode must consume bytes");
            assert!(
                used <= wire.len(),
                "{context}: consumed {used} bytes beyond input length {}",
                wire.len()
            );
            assert_resp_value_respects_limits(&decoded, limits, 0, context);
        }
        Ok(None) => {
            assert!(
                wire.is_empty() || !wire.ends_with(b"\r\n") || starts_length_prefixed_frame(wire),
                "{context}: complete-looking non-length-prefixed frame should not need more bytes"
            );
        }
        Err(error) => observe_decode_error(&error, context),
    }
}

fn observe_decode_error(error: &RedisError, context: &str) {
    assert!(
        !error.to_string().trim().is_empty(),
        "{context}: RESP3 attribute decode error should expose a diagnostic"
    );
}

fn starts_length_prefixed_frame(wire: &[u8]) -> bool {
    matches!(
        wire.first(),
        Some(b'$' | b'=' | b'!' | b'*' | b'%' | b'~' | b'>' | b'|')
    )
}

fn assert_resp_value_respects_limits(
    value: &RespValue,
    limits: &RedisProtocolLimits,
    depth: usize,
    context: &str,
) {
    assert!(
        depth <= limits.max_nesting_depth,
        "{context}: decoded RESP value exceeded nesting limit {}",
        limits.max_nesting_depth
    );

    match value {
        RespValue::SimpleString(s)
        | RespValue::Error(s)
        | RespValue::Double(s)
        | RespValue::BigNumber(s) => {
            assert!(
                !s.as_bytes().contains(&b'\r') && !s.as_bytes().contains(&b'\n'),
                "{context}: line-oriented RESP string retained a CR/LF byte"
            );
        }
        RespValue::Integer(_) | RespValue::Null | RespValue::Boolean(_) => {}
        RespValue::BulkString(Some(bytes)) | RespValue::BlobError(bytes) => {
            assert!(
                bytes.len() <= limits.max_bulk_string_len,
                "{context}: decoded byte payload exceeded max_bulk_string_len"
            );
        }
        RespValue::BulkString(None) => {}
        RespValue::Verbatim { format, payload } => {
            assert_eq!(
                format.len(),
                3,
                "{context}: RESP3 verbatim format marker must be exactly three bytes"
            );
            assert!(
                payload.len() <= limits.max_bulk_string_len,
                "{context}: decoded verbatim payload exceeded max_bulk_string_len"
            );
        }
        RespValue::Array(Some(items)) | RespValue::Set(items) | RespValue::Push(items) => {
            assert!(
                items.len() <= limits.max_array_len,
                "{context}: decoded aggregate exceeded max_array_len"
            );
            for item in items {
                assert_resp_value_respects_limits(item, limits, depth + 1, context);
            }
        }
        RespValue::Array(None) => {}
        RespValue::Map(pairs) | RespValue::Attribute(pairs) => {
            assert!(
                pairs.len() <= limits.max_array_len,
                "{context}: decoded pair aggregate exceeded max_array_len"
            );
            for (key, value) in pairs {
                assert_resp_value_respects_limits(key, limits, depth + 1, context);
                assert_resp_value_respects_limits(value, limits, depth + 1, context);
            }
        }
    }
}

impl FuzzLimits {
    fn normalized(self) -> RedisProtocolLimits {
        let max_array_len = usize::from(self.max_array_len).clamp(1, MAX_PAIRS);
        let max_nesting_depth = usize::from(self.max_nesting_depth).clamp(1, MAX_DEPTH);
        let max_bulk_string_len = usize::from(self.max_bulk_string_len).clamp(1, MAX_PAYLOAD_LEN);

        RedisProtocolLimits::new()
            .max_frame_size(MAX_WIRE_LEN)
            .max_array_len(max_array_len)
            .max_nesting_depth(max_nesting_depth)
            .max_bulk_string_len(max_bulk_string_len)
    }
}

fn canary_limits() -> RedisProtocolLimits {
    RedisProtocolLimits::new()
        .max_frame_size(MAX_WIRE_LEN)
        .max_array_len(MAX_PAIRS)
        .max_nesting_depth(MAX_DEPTH)
        .max_bulk_string_len(MAX_PAYLOAD_LEN)
}

fn deep_attribute_wire(depth: usize, leaf: &[u8]) -> Vec<u8> {
    let mut wire = Vec::new();
    for level in 0..depth {
        wire.extend_from_slice(b"|1\r\n");
        let key = [b'a', b'0' + (level % 10) as u8];
        encode_bulk(&key, &mut wire);
    }
    encode_bulk(leaf, &mut wire);
    wire
}

fn attribute_before_nested_aggregate(aggregate: AggregateShape) -> Vec<u8> {
    let mut wire = b"|1\r\n+meta\r\n:1\r\n".to_vec();
    encode_aggregate(aggregate, &mut wire);
    wire
}

fn nested_aggregate_contains_attribute(aggregate: AggregateShape) -> Vec<u8> {
    let mut wire = b"*2\r\n|1\r\n+meta\r\n+value\r\n".to_vec();
    encode_aggregate(aggregate, &mut wire);
    wire
}

fn malformed_attribute_prefix(prefix: LengthPrefix, tail: Vec<u8>) -> Vec<u8> {
    match prefix {
        LengthPrefix::Negative(n) => {
            let magnitude = i32::from(n).unsigned_abs().min(1024) + 1;
            format!("|-{magnitude}\r\n").into_bytes()
        }
        LengthPrefix::Overflow(digits) => {
            let mut wire = b"|9".to_vec();
            for digit in digits.into_iter().take(32) {
                wire.push(b'0' + (digit % 10));
            }
            wire.extend_from_slice(b"\r\n");
            wire
        }
        LengthPrefix::NonDigits(bytes) => {
            let mut wire = b"|".to_vec();
            for byte in bytes.into_iter().take(24) {
                let byte = if byte.is_ascii_digit() { b'x' } else { byte };
                if byte != b'\r' && byte != b'\n' {
                    wire.push(byte);
                }
            }
            wire.extend_from_slice(b"\r\n");
            wire
        }
        LengthPrefix::MissingCrlf(bytes) => {
            let mut wire = b"|".to_vec();
            wire.extend_from_slice(&bounded_payload(bytes));
            wire
        }
        LengthPrefix::TruncatedPair => {
            let mut wire = b"|1\r\n".to_vec();
            encode_bulk(&tail, &mut wire);
            wire
        }
    }
}

fn encode_aggregate(aggregate: AggregateShape, wire: &mut Vec<u8>) {
    match aggregate {
        AggregateShape::EmptyArray => wire.extend_from_slice(b"*0\r\n"),
        AggregateShape::ArrayWithBulk { payload } => {
            wire.extend_from_slice(b"*1\r\n");
            encode_bulk(&bounded_payload(payload), wire);
        }
        AggregateShape::ArrayWithMap { key, value } => {
            wire.extend_from_slice(b"*1\r\n%1\r\n");
            encode_bulk(&bounded_payload(key), wire);
            encode_bulk(&bounded_payload(value), wire);
        }
        AggregateShape::MapWithArray { key, value } => {
            wire.extend_from_slice(b"%1\r\n");
            encode_bulk(&bounded_payload(key), wire);
            wire.extend_from_slice(b"*1\r\n");
            encode_bulk(&bounded_payload(value), wire);
        }
        AggregateShape::SetWithBulk { payload } => {
            wire.extend_from_slice(b"~1\r\n");
            encode_bulk(&bounded_payload(payload), wire);
        }
    }
}

fn encode_bulk(bytes: &[u8], wire: &mut Vec<u8>) {
    let bytes = if bytes.len() > MAX_PAYLOAD_LEN {
        &bytes[..MAX_PAYLOAD_LEN]
    } else {
        bytes
    };
    wire.extend_from_slice(format!("${}\r\n", bytes.len()).as_bytes());
    wire.extend_from_slice(bytes);
    wire.extend_from_slice(b"\r\n");
}

fn bounded_payload(mut bytes: Vec<u8>) -> Vec<u8> {
    bytes.truncate(MAX_PAYLOAD_LEN);
    bytes
}

fn bounded_wire(mut bytes: Vec<u8>) -> Vec<u8> {
    bytes.truncate(MAX_WIRE_LEN.saturating_sub(1));
    bytes
}

fn bounded_wire_ref(bytes: &[u8]) -> &[u8] {
    if bytes.len() > MAX_WIRE_LEN {
        &bytes[..MAX_WIRE_LEN]
    } else {
        bytes
    }
}
