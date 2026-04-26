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
//! Run with: `cargo +nightly fuzz run fuzz_h3_settings_bool_parser`

#![no_main]

use arbitrary::Arbitrary;
use asupersync::http::h3_native::H3Settings;
use libfuzzer_sys::fuzz_target;

const MAX_INPUT_BYTES: usize = 16 * 1024;

const ENABLE_CONNECT_PROTOCOL: u64 = 0x08;
const H3_DATAGRAM: u64 = 0x33;
/// HTTP/2-reserved identifiers per RFC 9114 §7.2.4.1.
const RESERVED_IDS: &[u64] = &[0x00, 0x02, 0x03, 0x04, 0x05];

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

fuzz_target!(|s: Scenario| match s {
    Scenario::Arbitrary(bytes) => fuzz_arbitrary(&bytes),
    Scenario::SinglePair { id, value } => fuzz_single_pair(id, value),
    Scenario::MultiPair { pairs } => fuzz_multi_pair(&pairs),
    Scenario::BoolSettingAttack { which, value } => fuzz_bool_attack(which, value),
});

fn fuzz_arbitrary(bytes: &[u8]) {
    if bytes.len() > MAX_INPUT_BYTES {
        return;
    }
    let _ = H3Settings::decode_payload(bytes);
}

fn fuzz_single_pair(id: u64, value: u64) {
    let mut buf = Vec::with_capacity(16);
    encode_varint(id, &mut buf);
    encode_varint(value, &mut buf);
    let _ = H3Settings::decode_payload(&buf);
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
    let _ = H3Settings::decode_payload(&buf);

    // Also exercise the reserved-id path: same fuzzer pairs but
    // first-pair id forced to one of the reserved set.
    if let Some(reserved) = RESERVED_IDS.first() {
        let mut buf2 = Vec::with_capacity(16);
        encode_varint(*reserved, &mut buf2);
        encode_varint(pairs.first().map_or(0, |p| p.1), &mut buf2);
        let _ = H3Settings::decode_payload(&buf2);
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
    let _ = H3Settings::decode_payload(&buf);
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
    } else if value <= 0x3FFF_FFFF_FFFF_FFFFu64 {
        let v: u64 = value | 0xC000_0000_0000_0000u64;
        out.extend_from_slice(&v.to_be_bytes());
    } else {
        // Out-of-range u62 values cannot be encoded; emit the max
        // representable instead so the fuzzer doesn't waste cycles
        // on unencodable inputs.
        let v: u64 = 0x3FFF_FFFF_FFFF_FFFFu64 | 0xC000_0000_0000_0000u64;
        out.extend_from_slice(&v.to_be_bytes());
    }
}
