//! br-asupersync-ev48ox: focused fuzz target for the H3 SETTINGS bool
//! parser at `src/http/h3_native.rs::parse_bool_setting`.
//!
//! `parse_bool_setting` is file-private but reachable from the public
//! [`H3Settings::decode_payload`] entry point: every SETTINGS frame the
//! peer sends with `ENABLE_CONNECT_PROTOCOL` (0x08) or `H3_DATAGRAM`
//! (0x33) drives a bool-setting parse with attacker-controlled `value`.
//! The function MUST reject every value other than 0 or 1 with
//! `InvalidSettingValue`; a buggy implementation that silently coerced
//! out-of-range values to `true` (or panicked) would let a peer flip a
//! protocol-level capability bit on the receiving connection.
//!
//! Attack surface: SETTINGS frame payloads on the H3 control stream.
//!
//! Malformed shapes:
//!   * boolean settings with values 2..=u64::MAX (must be rejected)
//!   * varint-encoded boolean values at the upper varint boundary
//!     (`max u62 = 2^62 - 1` per RFC 9000 §16)
//!   * duplicate setting IDs in the same frame (must error per RFC
//!     9114 §7.2.4)
//!   * HTTP/2-reserved IDs (0x00, 0x02..=0x05) — must be rejected
//!     even with valid bool values (RFC 9114 §7.2.4.1)
//!   * Bare H3_DATAGRAM with `false` followed by ENABLE_CONNECT_PROTOCOL
//!     — exercises the multi-setting path
//!
//! The harness must never panic. Decoder errors are expected; a process
//! abort, OOM, or hang is the failure signal.
//!
//! Run with: `rch exec -- env CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_fuzz_h3_settings_bool_parser cargo +nightly fuzz run fuzz_h3_settings_bool_parser`

#![no_main]

use arbitrary::Arbitrary;
use asupersync::http::h3_native::{H3NativeError, H3Settings};
use libfuzzer_sys::fuzz_target;
use std::sync::OnceLock;

const MAX_INPUT_BYTES: usize = 16 * 1024;
const MAX_U62: u64 = 0x3FFF_FFFF_FFFF_FFFF;

const ENABLE_CONNECT_PROTOCOL: u64 = 0x08;
const H3_DATAGRAM: u64 = 0x33;
const QPACK_MAX_TABLE_CAPACITY: u64 = 0x01;
const MAX_FIELD_SECTION_SIZE: u64 = 0x06;
const QPACK_BLOCKED_STREAMS: u64 = 0x07;
/// HTTP/2-reserved identifiers per RFC 9114 §7.2.4.1.
const RESERVED_IDS: &[u64] = &[0x00, 0x02, 0x03, 0x04, 0x05];

static FIXED_SETTINGS_CANARIES: OnceLock<()> = OnceLock::new();

#[derive(Arbitrary, Debug)]
enum Scenario {
    /// Raw arbitrary bytes feeding `H3Settings::decode_payload` directly.
    /// Broadest coverage; libFuzzer's coverage-guided mutator finds the
    /// interesting varint shapes on its own.
    Arbitrary(Vec<u8>),

    /// Targeted (id, value) pair encoded via QUIC varint. The fuzzer
    /// drives `id` and `value` over their full u64 range so we exercise
    /// every (id, value) cell — including reserved IDs, bool IDs with
    /// out-of-range values, and unknown IDs (which must be retained
    /// without rejection per RFC 9114 §7.2.4.2).
    SinglePair { id: u64, value: u64 },

    /// Sequence of (id, value) pairs encoded back-to-back. Exercises
    /// duplicate-ID detection (line 274 in h3_native.rs:
    /// `seen_ids.insert(id)`) AND multi-bool-setting flow.
    MultiPair { pairs: Vec<(u64, u64)> },

    /// Targeted bool-setting attack: emit ENABLE_CONNECT_PROTOCOL or
    /// H3_DATAGRAM with `value` ranging the full u64. The harness
    /// expects the decoder to reject every non-{0,1} value via
    /// `InvalidSettingValue` — a panic, OOM, or accept here is a
    /// security-grade finding.
    BoolSettingAttack {
        /// `false` selects ENABLE_CONNECT_PROTOCOL; `true` selects H3_DATAGRAM.
        which: bool,
        value: u64,
    },
}

fuzz_target!(|s: Scenario| {
    FIXED_SETTINGS_CANARIES.get_or_init(test_fixed_settings_canaries);

    match s {
        Scenario::Arbitrary(bytes) => fuzz_arbitrary(&bytes),
        Scenario::SinglePair { id, value } => fuzz_single_pair(id, value),
        Scenario::MultiPair { pairs } => fuzz_multi_pair(&pairs),
        Scenario::BoolSettingAttack { which, value } => {
            fuzz_bool_attack(which, value);
        }
    }
});

fn fuzz_arbitrary(bytes: &[u8]) {
    if bytes.len() > MAX_INPUT_BYTES {
        return;
    }
    observe_decode_result(H3Settings::decode_payload(bytes));
}

fn fuzz_single_pair(id: u64, value: u64) {
    let mut buf = Vec::with_capacity(16);
    encode_varint(id, &mut buf);
    encode_varint(value, &mut buf);
    assert_single_pair_result(clamp_to_u62(id), clamp_to_u62(value), &buf);
}

fn fuzz_multi_pair(pairs: &[(u64, u64)]) {
    let mut buf = Vec::with_capacity(MAX_INPUT_BYTES);
    for (id, value) in pairs.iter().take(64) {
        encode_varint(*id, &mut buf);
        encode_varint(*value, &mut buf);
        if buf.len() > MAX_INPUT_BYTES {
            break;
        }
    }
    observe_decode_result(H3Settings::decode_payload(&buf));

    // Also exercise the reserved-id path: same fuzzer pairs but
    // first-pair id forced to one of the reserved set.
    if let Some(reserved) = RESERVED_IDS.first() {
        let mut buf2 = Vec::with_capacity(16);
        encode_varint(*reserved, &mut buf2);
        encode_varint(pairs.first().map_or(0, |p| p.1), &mut buf2);
        expect_invalid_setting_value(&buf2, *reserved);
    }
}

fn fuzz_bool_attack(which: bool, value: u64) {
    let id = if which {
        H3_DATAGRAM
    } else {
        ENABLE_CONNECT_PROTOCOL
    };

    let mut buf = Vec::with_capacity(16);
    encode_varint(id, &mut buf);
    encode_varint(value, &mut buf);
    assert_bool_setting_result(id, clamp_to_u62(value), &buf);
}

fn assert_single_pair_result(id: u64, value: u64, payload: &[u8]) {
    if RESERVED_IDS.contains(&id) {
        expect_invalid_setting_value(payload, id);
        return;
    }

    match id {
        ENABLE_CONNECT_PROTOCOL | H3_DATAGRAM => assert_bool_setting_result(id, value, payload),
        QPACK_MAX_TABLE_CAPACITY | MAX_FIELD_SECTION_SIZE | QPACK_BLOCKED_STREAMS => {
            let settings = expect_settings_ok(payload);
            match id {
                QPACK_MAX_TABLE_CAPACITY => {
                    assert_eq!(settings.qpack_max_table_capacity, Some(value));
                }
                MAX_FIELD_SECTION_SIZE => {
                    assert_eq!(settings.max_field_section_size, Some(value));
                }
                QPACK_BLOCKED_STREAMS => {
                    assert_eq!(settings.qpack_blocked_streams, Some(value));
                }
                _ => unreachable!("matched known non-bool setting id"),
            }
        }
        _ => {
            let settings = expect_settings_ok(payload);
            assert!(
                settings
                    .unknown
                    .iter()
                    .any(|setting| setting.id == id && setting.value == value),
                "unknown setting should be retained exactly: id=0x{id:x}, value={value}"
            );
        }
    }
}

fn assert_bool_setting_result(id: u64, value: u64, payload: &[u8]) {
    match value {
        0 | 1 => {
            let settings = expect_settings_ok(payload);
            let expected = Some(value == 1);
            match id {
                ENABLE_CONNECT_PROTOCOL => {
                    assert_eq!(settings.enable_connect_protocol, expected);
                    assert_eq!(settings.h3_datagram, None);
                }
                H3_DATAGRAM => {
                    assert_eq!(settings.h3_datagram, expected);
                    assert_eq!(settings.enable_connect_protocol, None);
                }
                _ => unreachable!("bool assertion called for non-bool setting id"),
            }
        }
        _ => expect_invalid_setting_value(payload, id),
    }
}

fn test_fixed_settings_canaries() {
    let enable_false = settings_payload(&[(ENABLE_CONNECT_PROTOCOL, 0)]);
    assert_bool_setting_result(ENABLE_CONNECT_PROTOCOL, 0, &enable_false);

    let datagram_true = settings_payload(&[(H3_DATAGRAM, 1)]);
    assert_bool_setting_result(H3_DATAGRAM, 1, &datagram_true);

    let enable_invalid = settings_payload(&[(ENABLE_CONNECT_PROTOCOL, 2)]);
    expect_invalid_setting_value(&enable_invalid, ENABLE_CONNECT_PROTOCOL);

    let datagram_invalid = settings_payload(&[(H3_DATAGRAM, MAX_U62)]);
    expect_invalid_setting_value(&datagram_invalid, H3_DATAGRAM);

    let duplicate_bool =
        settings_payload(&[(ENABLE_CONNECT_PROTOCOL, 0), (ENABLE_CONNECT_PROTOCOL, 1)]);
    expect_duplicate_setting(&duplicate_bool, ENABLE_CONNECT_PROTOCOL);

    let reserved = settings_payload(&[(RESERVED_IDS[0], 0)]);
    expect_invalid_setting_value(&reserved, RESERVED_IDS[0]);

    let unknown_id = 0x21;
    let unknown_value = 7;
    let unknown = settings_payload(&[(unknown_id, unknown_value)]);
    let settings = expect_settings_ok(&unknown);
    assert_eq!(settings.unknown.len(), 1);
    assert_eq!(settings.unknown[0].id, unknown_id);
    assert_eq!(settings.unknown[0].value, unknown_value);
}

fn settings_payload(pairs: &[(u64, u64)]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(pairs.len() * 16);
    for (id, value) in pairs {
        encode_varint(*id, &mut buf);
        encode_varint(*value, &mut buf);
    }
    buf
}

fn expect_settings_ok(payload: &[u8]) -> H3Settings {
    match H3Settings::decode_payload(payload) {
        Ok(settings) => settings,
        Err(error) => panic!("expected valid SETTINGS payload, got {error:?}"),
    }
}

fn expect_invalid_setting_value(payload: &[u8], expected_id: u64) {
    match H3Settings::decode_payload(payload) {
        Err(H3NativeError::InvalidSettingValue(id)) => {
            assert_eq!(id, expected_id, "InvalidSettingValue id mismatch");
        }
        Ok(settings) => panic!("expected InvalidSettingValue({expected_id}), got {settings:?}"),
        Err(error) => panic!("expected InvalidSettingValue({expected_id}), got {error:?}"),
    }
}

fn expect_duplicate_setting(payload: &[u8], expected_id: u64) {
    match H3Settings::decode_payload(payload) {
        Err(H3NativeError::DuplicateSetting(id)) => {
            assert_eq!(id, expected_id, "DuplicateSetting id mismatch");
        }
        Ok(settings) => panic!("expected DuplicateSetting({expected_id}), got {settings:?}"),
        Err(error) => panic!("expected DuplicateSetting({expected_id}), got {error:?}"),
    }
}

fn observe_decode_result(result: Result<H3Settings, H3NativeError>) {
    match result {
        Ok(settings) => {
            for setting in &settings.unknown {
                assert!(
                    !RESERVED_IDS.contains(&setting.id),
                    "reserved setting id must not be retained as unknown"
                );
            }
        }
        Err(error) => {
            let display = format!("{error}");
            assert!(
                !display.is_empty(),
                "decode error display should not be empty"
            );
        }
    }
}

const fn clamp_to_u62(value: u64) -> u64 {
    if value <= MAX_U62 { value } else { MAX_U62 }
}

/// QUIC varint encoder per RFC 9000 §16. Mirrors `encode_varint` in
/// `src/http/h3_native.rs` but is reproduced here so the fuzz target
/// stays decoupled from the crate's private encoding helpers.
fn encode_varint(value: u64, out: &mut Vec<u8>) {
    if value <= 0x3F {
        out.push(value as u8);
    } else if value <= 0x3FFF {
        let v = value as u16 | 0x4000;
        out.extend_from_slice(&v.to_be_bytes());
    } else if value <= 0x3FFF_FFFF {
        let v = value as u32 | 0x8000_0000;
        out.extend_from_slice(&v.to_be_bytes());
    } else if value <= MAX_U62 {
        let v: u64 = value | 0xC000_0000_0000_0000u64;
        out.extend_from_slice(&v.to_be_bytes());
    } else {
        // Out-of-range u62 values cannot be encoded; emit the max
        // representable instead so the fuzzer doesn't waste cycles
        // on unencodable inputs.
        let v: u64 = MAX_U62 | 0xC000_0000_0000_0000u64;
        out.extend_from_slice(&v.to_be_bytes());
    }
}
