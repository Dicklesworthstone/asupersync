#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

use asupersync::messaging::redis::{RedisProtocolLimits, RespValue};

const MAX_WIRE_LEN: usize = 16 * 1024;
const MAX_PAYLOAD_LEN: usize = 256;
const MAX_PAIRS: usize = 32;
const MAX_DEPTH: usize = 48;

#[derive(Debug, Arbitrary)]
struct MapParseCase {
    limits: FuzzLimits,
    scenario: MapScenario,
}

#[derive(Debug, Arbitrary)]
struct FuzzLimits {
    max_array_len: u8,
    max_nesting_depth: u8,
    max_bulk_string_len: u16,
}

#[derive(Debug, Arbitrary)]
enum MapScenario {
    EmptyMap,
    OddLengthKeys {
        keys: Vec<Vec<u8>>,
        values: Vec<LeafValue>,
    },
    DeeplyNestedValues {
        depth: u8,
        leaf: Vec<u8>,
    },
    MalformedLengthPrefix {
        prefix: LengthPrefix,
        tail: Vec<u8>,
    },
    StreamedOddChildren {
        key: LeafValue,
        include_terminator: bool,
    },
    RawMapBytes {
        data: Vec<u8>,
    },
}

#[derive(Clone, Debug, Arbitrary)]
enum LeafValue {
    Simple(Vec<u8>),
    Bulk(Vec<u8>),
    Integer(i64),
    Null,
    Boolean(bool),
    EmptyArray,
    EmptyMap,
}

#[derive(Debug, Arbitrary)]
enum LengthPrefix {
    Negative(i16),
    Overflow(Vec<u8>),
    NonDigits(Vec<u8>),
    MissingCrlf(Vec<u8>),
    DeclaredTooLarge(u16),
    TruncatedPairs(u8),
}

fuzz_target!(|case: MapParseCase| {
    let limits = case.limits.normalized();

    parse_without_harness_panic(b"%0\r\n", &limits);
    parse_without_harness_panic(b"%?\r\n.\r\n", &limits);
    parse_without_harness_panic(b"%?\r\n+odd\r\n.\r\n", &limits);
    parse_without_harness_panic(deep_map_wire(24, b"seed").as_slice(), &limits);
    parse_without_harness_panic(b"%-1\r\n", &limits);
    parse_without_harness_panic(b"%999999999999999999999999\r\n", &limits);

    fuzz_map_parse(case.scenario, &limits);
});

fn fuzz_map_parse(scenario: MapScenario, limits: &RedisProtocolLimits) {
    let wire = match scenario {
        MapScenario::EmptyMap => b"%0\r\n".to_vec(),
        MapScenario::OddLengthKeys { keys, values } => odd_length_key_map(keys, values),
        MapScenario::DeeplyNestedValues { depth, leaf } => {
            let depth = usize::from(depth).min(MAX_DEPTH);
            deep_map_wire(depth, &bounded_payload(leaf))
        }
        MapScenario::MalformedLengthPrefix { prefix, tail } => {
            malformed_length_prefix(prefix, bounded_payload(tail))
        }
        MapScenario::StreamedOddChildren {
            key,
            include_terminator,
        } => {
            let mut wire = b"%?\r\n".to_vec();
            encode_leaf(&key, &mut wire);
            if include_terminator {
                wire.extend_from_slice(b".\r\n");
            }
            wire
        }
        MapScenario::RawMapBytes { data } => {
            let mut wire = Vec::with_capacity(data.len().saturating_add(1).min(MAX_WIRE_LEN));
            wire.push(b'%');
            wire.extend_from_slice(&bounded_wire(data));
            wire
        }
    };

    parse_without_harness_panic(&wire, limits);
}

fn parse_without_harness_panic(wire: &[u8], limits: &RedisProtocolLimits) {
    let wire = if wire.len() > MAX_WIRE_LEN {
        &wire[..MAX_WIRE_LEN]
    } else {
        wire
    };
    let _ = RespValue::try_decode_with_limits(wire, limits);
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

fn odd_length_key_map(keys: Vec<Vec<u8>>, values: Vec<LeafValue>) -> Vec<u8> {
    let pair_count = keys.len().min(values.len()).min(MAX_PAIRS);
    let mut wire = format!("%{pair_count}\r\n").into_bytes();

    for (key, value) in keys.into_iter().zip(values).take(pair_count) {
        encode_bulk(&odd_length_payload(key), &mut wire);
        encode_leaf(&value, &mut wire);
    }

    wire
}

fn deep_map_wire(depth: usize, leaf: &[u8]) -> Vec<u8> {
    let mut wire = Vec::new();
    for level in 0..depth {
        wire.extend_from_slice(b"%1\r\n");
        let key = [b'k', b'0' + (level % 10) as u8, b'x'];
        encode_bulk(&key, &mut wire);
    }
    encode_bulk(leaf, &mut wire);
    wire
}

fn malformed_length_prefix(prefix: LengthPrefix, tail: Vec<u8>) -> Vec<u8> {
    match prefix {
        LengthPrefix::Negative(n) => {
            let magnitude = i32::from(n).unsigned_abs().min(1024) + 1;
            format!("%-{magnitude}\r\n").into_bytes()
        }
        LengthPrefix::Overflow(digits) => {
            let mut wire = b"%9".to_vec();
            for digit in digits.into_iter().take(32) {
                wire.push(b'0' + (digit % 10));
            }
            wire.extend_from_slice(b"\r\n");
            wire
        }
        LengthPrefix::NonDigits(bytes) => {
            let mut wire = b"%".to_vec();
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
            let mut wire = b"%".to_vec();
            wire.extend_from_slice(&bounded_payload(bytes));
            wire
        }
        LengthPrefix::DeclaredTooLarge(extra) => {
            let declared = MAX_PAIRS + 1 + usize::from(extra % 128);
            let mut wire = format!("%{declared}\r\n").into_bytes();
            encode_bulk(b"k", &mut wire);
            encode_bulk(&tail, &mut wire);
            wire
        }
        LengthPrefix::TruncatedPairs(actual_pairs) => {
            let actual_pairs = usize::from(actual_pairs).min(MAX_PAIRS / 2);
            let declared = actual_pairs.saturating_add(1);
            let mut wire = format!("%{declared}\r\n").into_bytes();
            for index in 0..actual_pairs {
                let key = [b'k', b'0' + (index % 10) as u8];
                encode_bulk(&key, &mut wire);
                encode_bulk(&tail, &mut wire);
            }
            wire
        }
    }
}

fn encode_leaf(value: &LeafValue, wire: &mut Vec<u8>) {
    match value {
        LeafValue::Simple(bytes) => {
            wire.push(b'+');
            for byte in bounded_payload(bytes.clone()) {
                if byte != b'\r' && byte != b'\n' {
                    wire.push(byte);
                }
            }
            wire.extend_from_slice(b"\r\n");
        }
        LeafValue::Bulk(bytes) => encode_bulk(&bounded_payload(bytes.clone()), wire),
        LeafValue::Integer(n) => wire.extend_from_slice(format!(":{n}\r\n").as_bytes()),
        LeafValue::Null => wire.extend_from_slice(b"_\r\n"),
        LeafValue::Boolean(true) => wire.extend_from_slice(b"#t\r\n"),
        LeafValue::Boolean(false) => wire.extend_from_slice(b"#f\r\n"),
        LeafValue::EmptyArray => wire.extend_from_slice(b"*0\r\n"),
        LeafValue::EmptyMap => wire.extend_from_slice(b"%0\r\n"),
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

fn odd_length_payload(mut bytes: Vec<u8>) -> Vec<u8> {
    bytes.truncate(MAX_PAYLOAD_LEN.saturating_sub(1));
    if bytes.is_empty() {
        bytes.push(b'k');
    }
    if bytes.len() % 2 == 0 {
        bytes.push(b'x');
    }
    bytes
}

fn bounded_payload(mut bytes: Vec<u8>) -> Vec<u8> {
    bytes.truncate(MAX_PAYLOAD_LEN);
    bytes
}

fn bounded_wire(mut bytes: Vec<u8>) -> Vec<u8> {
    bytes.truncate(MAX_WIRE_LEN.saturating_sub(1));
    bytes
}
