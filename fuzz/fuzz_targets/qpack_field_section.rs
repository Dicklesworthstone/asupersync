//! Fuzz target for QPACK encoded field section parsing in `h3_native.rs`.
//!
//! Focuses on the wire-level field section parser from RFC 9204 with
//! structure-aware scenarios for:
//! - static-table indexed field lines
//! - dynamic-table indexed references that must be rejected without state
//! - literal field lines with static-name references
//! - prefixed-integer overflow rejection

#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use asupersync::http::h3_native::{
    H3NativeError, H3QpackMode, QpackFieldPlan, qpack_decode_field_section,
    qpack_encode_field_section, qpack_plan_to_header_fields,
};
use libfuzzer_sys::fuzz_target;

const VALID_STATIC_INDICES: &[u64] = &[
    2, 4, 5, 6, 12, 14, 29, 31, 46, 53, 59, 62, 72, 83, 90, 95, 98,
];

const VALID_NAME_REFERENCES: &[(u64, &str)] = &[
    (29, "accept"),
    (53, "content-type"),
    (72, "accept-language"),
    (95, "user-agent"),
];

const MAX_VALUE_LEN: usize = 64;

#[derive(Arbitrary, Debug, Clone, Copy)]
enum Scenario {
    StaticIndexed,
    DynamicIndexReference,
    LiteralWithNameReference,
    PrefixIntegerOverflow,
}

#[derive(Arbitrary, Debug, Clone, Copy)]
enum Mode {
    StaticOnly,
    DynamicTableAllowed,
}

impl From<Mode> for H3QpackMode {
    fn from(mode: Mode) -> Self {
        match mode {
            Mode::StaticOnly => H3QpackMode::StaticOnly,
            Mode::DynamicTableAllowed => H3QpackMode::DynamicTableAllowed,
        }
    }
}

#[derive(Arbitrary, Debug)]
struct FuzzInput {
    scenario: Scenario,
    mode: Mode,
    static_case: u8,
    dynamic_index: u8,
    name_ref_case: u8,
    value: Vec<u8>,
}

fuzz_target!(|data: &[u8]| {
    let mut unstructured = Unstructured::new(data);
    let Ok(mut input) = FuzzInput::arbitrary(&mut unstructured) else {
        return;
    };
    input.value.truncate(MAX_VALUE_LEN);
    let mode = H3QpackMode::from(input.mode);

    match input.scenario {
        Scenario::StaticIndexed => {
            let index = VALID_STATIC_INDICES[usize::from(input.static_case) % VALID_STATIC_INDICES.len()];
            let wire =
                qpack_encode_field_section(&[QpackFieldPlan::StaticIndex(index)]).expect("known static index");
            let decoded = qpack_decode_field_section(&wire, mode).expect("static field section");
            assert_eq!(decoded.len(), 1);
            match &decoded[0] {
                QpackFieldPlan::StaticIndex(decoded_index) => assert_eq!(*decoded_index, index),
                other => panic!("expected static index, got {other:?}"),
            }
            let expanded = qpack_plan_to_header_fields(&decoded).expect("expand static field");
            assert_eq!(expanded.len(), 1);
        }
        Scenario::DynamicIndexReference => {
            let wire = build_dynamic_index_reference(u64::from(input.dynamic_index));
            let err = qpack_decode_field_section(&wire, mode).expect_err("dynamic references require state");
            assert_policy_error(
                err,
                "dynamic qpack index references require dynamic table state",
            );
        }
        Scenario::LiteralWithNameReference => {
            let (name_index, expected_name) =
                VALID_NAME_REFERENCES[usize::from(input.name_ref_case) % VALID_NAME_REFERENCES.len()];
            let expected_value = sanitize_ascii(&input.value);
            let wire = build_literal_with_name_reference(name_index, expected_value.as_bytes());
            let decoded = qpack_decode_field_section(&wire, mode).expect("literal with name ref");
            assert_eq!(decoded.len(), 1);
            match &decoded[0] {
                QpackFieldPlan::Literal { name, value } => {
                    assert_eq!(name, expected_name);
                    assert_eq!(value, &expected_value);
                }
                other => panic!("expected literal field line, got {other:?}"),
            }
            let expanded = qpack_plan_to_header_fields(&decoded).expect("expand literal field");
            assert_eq!(expanded, vec![(expected_name.to_string(), expected_value)]);
        }
        Scenario::PrefixIntegerOverflow => {
            let err =
                qpack_decode_field_section(&build_prefix_integer_overflow(), mode).expect_err("overflow");
            assert_invalid_frame(err, "qpack integer overflow");
        }
    }
});

fn build_dynamic_index_reference(index: u64) -> Vec<u8> {
    let mut wire = vec![0x00, 0x00];
    encode_prefixed_int(&mut wire, 0b1000_0000, 6, index);
    wire
}

fn build_literal_with_name_reference(name_index: u64, value: &[u8]) -> Vec<u8> {
    let mut wire = vec![0x00, 0x00];
    encode_prefixed_int(&mut wire, 0b0101_0000, 4, name_index);
    encode_string(&mut wire, 0x00, 7, value);
    wire
}

fn build_prefix_integer_overflow() -> Vec<u8> {
    let mut wire = vec![0xFFu8];
    wire.extend(std::iter::repeat_n(0x80, 9));
    wire.push(0x02);
    wire
}

fn encode_prefixed_int(out: &mut Vec<u8>, prefix_bits: u8, prefix_len: u8, value: u64) {
    let max_prefix = (1u64 << prefix_len) - 1;
    if value < max_prefix {
        out.push(prefix_bits | value as u8);
        return;
    }

    out.push(prefix_bits | max_prefix as u8);
    let mut remaining = value - max_prefix;
    while remaining >= 128 {
        out.push((remaining as u8 & 0x7F) | 0x80);
        remaining >>= 7;
    }
    out.push(remaining as u8);
}

fn encode_string(out: &mut Vec<u8>, prefix_bits: u8, prefix_len: u8, value: &[u8]) {
    encode_prefixed_int(out, prefix_bits, prefix_len, value.len() as u64);
    out.extend_from_slice(value);
}

fn sanitize_ascii(value: &[u8]) -> String {
    value
        .iter()
        .map(|byte| char::from(b'a' + (byte % 26)))
        .collect()
}

fn assert_policy_error(err: H3NativeError, expected: &'static str) {
    match err {
        H3NativeError::QpackPolicy(message) => assert_eq!(message, expected),
        other => panic!("expected qpack policy error, got {other:?}"),
    }
}

fn assert_invalid_frame(err: H3NativeError, expected: &'static str) {
    match err {
        H3NativeError::InvalidFrame(message) => assert_eq!(message, expected),
        other => panic!("expected invalid frame error, got {other:?}"),
    }
}
