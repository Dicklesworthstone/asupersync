//! br-asupersync-1pafo2: focused fuzz target for the QPACK string decoder
//! at `src/http/h3_native.rs::qpack_decode_string`.
//!
//! `qpack_decode_string` is file-private but every literal-name and
//! literal-value field representation walks through it from the public
//! [`qpack_decode_field_section`] entry point. The decoder:
//!
//!   * delegates length parsing to `qpack_decode_prefixed_int` (covered
//!     by sibling fuzzer `fuzz_h3_qpack_prefixed_integer`),
//!   * rejects Huffman-flagged strings in static mode (line 1822-1825),
//!   * UTF-8 validates the payload (line 1835),
//!   * bounds-checks `len` against remaining input (line 1831).
//!
//! Attack surface: every QPACK literal-name / literal-value the peer sends.
//!
//! Malformed shapes the harness exercises:
//!   * Invalid UTF-8 in the payload bytes
//!   * Length declared > remaining buffer (truncation)
//!   * Length values past `usize::MAX` (try_into failure path)
//!   * Huffman-flagged literals (must be rejected in StaticOnly mode)
//!   * Zero-length strings, single-byte strings, max-prefix-saturated strings
//!
//! The harness must never panic. Decoder errors are expected; a process
//! abort, OOM, or hang is the failure signal.
//!
//! Run with: `rch exec -- env CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_fuzz_h3_qpack_string_decode cargo +nightly fuzz run fuzz_h3_qpack_string_decode`

#![no_main]

use arbitrary::Arbitrary;
use asupersync::http::h3_native::{
    H3NativeError, H3QpackMode, QpackFieldPlan, qpack_decode_field_section,
};
use libfuzzer_sys::fuzz_target;
use std::sync::OnceLock;

const MAX_INPUT_BYTES: usize = 64 * 1024;
const FIELD_SECTION_PREFIX: [u8; 2] = [0x00, 0x00];
static FIXED_STRING_CANARIES: OnceLock<()> = OnceLock::new();

#[derive(Arbitrary, Debug)]
enum Scenario {
    /// Raw arbitrary bytes — broadest coverage of the decoder's surface.
    Arbitrary(Vec<u8>),

    /// Constructs a literal-name field representation with attacker-controlled
    /// payload. The leading byte's representation tag is fuzzed; the
    /// length-prefix is forced to saturate so the continuation loop runs.
    LiteralNameWithPayload {
        /// Top 4 bits of the first byte select the representation kind.
        /// QPACK uses 0010xxxx, 0011xxxx, 0100xxxx, 0101xxxx etc. for
        /// literal name; we let the fuzzer probe all of them.
        repr_high: u8,
        /// Whether to set the Huffman flag — toggling this exercises the
        /// huffman_bit rejection path in static mode.
        huffman: bool,
        /// Length declared in the prefixed integer. Forced into a small
        /// range so we land on truncation boundaries (declared > available).
        declared_len: u8,
        /// Actual payload bytes the harness ships. May be shorter than
        /// `declared_len` (truncation) or longer (extra bytes ignored by
        /// the decoder; lets us exercise post-string trailing data too).
        payload: Vec<u8>,
    },

    /// Multi-section input — multiple literal-name/value entries back to
    /// back. Tests that the decoder advances correctly across sections
    /// and doesn't accumulate state from a malformed earlier entry.
    MultiSection { sections: Vec<Vec<u8>> },

    /// Length-overflow shape: a literal whose declared length is encoded
    /// via maxed-out prefixed-int continuations. Stresses the
    /// `try_into` u64→usize cast and the `saturating_sub` boundary.
    OverlongDeclaredLength {
        repr_high: u8,
        /// Number of all-`0x80` continuation bytes (capped at 9 by the
        /// decoder's shift>56 guard).
        continuation_count: u8,
    },
}

fuzz_target!(|s: Scenario| {
    FIXED_STRING_CANARIES.get_or_init(test_fixed_string_canaries);

    match s {
        Scenario::Arbitrary(bytes) => {
            fuzz_arbitrary(&bytes);
        }
        Scenario::LiteralNameWithPayload {
            repr_high,
            huffman,
            declared_len,
            payload,
        } => {
            fuzz_literal_name(repr_high, huffman, declared_len, &payload);
        }
        Scenario::MultiSection { sections } => {
            fuzz_multi_section(&sections);
        }
        Scenario::OverlongDeclaredLength {
            repr_high,
            continuation_count,
        } => {
            fuzz_overlong_length(repr_high, continuation_count);
        }
    }
});

fn fuzz_arbitrary(bytes: &[u8]) {
    if bytes.len() > MAX_INPUT_BYTES {
        return;
    }
    observe_decode_result(qpack_decode_field_section(bytes, H3QpackMode::StaticOnly));
}

fn fuzz_literal_name(repr_high: u8, huffman: bool, declared_len: u8, payload: &[u8]) {
    // Build a representation byte:
    //  - high 4 bits: representation tag from fuzzer
    //  - bit 3: huffman flag (when prefix_len < 8)
    //  - low 3 bits: length prefix (saturated to 0x07 to force continuation)
    let huffman_bit = if huffman { 0x08 } else { 0x00 };
    let first = (repr_high & 0xF0) | huffman_bit | 0x07;

    let take = payload.len().min(MAX_INPUT_BYTES - 2);

    let mut buf = Vec::with_capacity(FIELD_SECTION_PREFIX.len() + 2 + take);
    buf.extend_from_slice(&FIELD_SECTION_PREFIX);
    buf.push(first);
    // Length continuation: declared_len drives the multi-byte int. We
    // only emit one continuation byte to keep the length small enough
    // for libFuzzer to explore the truncation boundary.
    buf.push(declared_len);
    buf.extend_from_slice(&payload[..take]);

    observe_decode_result(qpack_decode_field_section(&buf, H3QpackMode::StaticOnly));
}

fn fuzz_multi_section(sections: &[Vec<u8>]) {
    let mut buf = Vec::with_capacity(MAX_INPUT_BYTES);
    for section in sections.iter().take(8) {
        if buf.len() + section.len() > MAX_INPUT_BYTES {
            break;
        }
        buf.extend_from_slice(section);
    }
    observe_decode_result(qpack_decode_field_section(&buf, H3QpackMode::StaticOnly));
}

fn fuzz_overlong_length(repr_high: u8, continuation_count: u8) {
    let count = continuation_count.min(16) as usize;
    let mut buf = Vec::with_capacity(FIELD_SECTION_PREFIX.len() + 2 + count);
    buf.extend_from_slice(&FIELD_SECTION_PREFIX);

    // Representation byte with saturated 7-bit length prefix (prefix_len = 7
    // so the integer continues into following bytes).
    buf.push((repr_high & 0x80) | 0x7F);
    // All-0x80 continuations push the integer toward overflow.
    buf.extend(std::iter::repeat_n(0x80, count));
    // Final non-continuation byte to terminate cleanly.
    buf.push(0x00);

    observe_decode_result(qpack_decode_field_section(&buf, H3QpackMode::StaticOnly));
}

fn test_fixed_string_canaries() {
    let empty = FIELD_SECTION_PREFIX.to_vec();
    let decoded = expect_decode_ok(&empty);
    assert!(
        decoded.is_empty(),
        "empty field section should decode empty"
    );

    let valid_literal = literal_name_value_section(b"a", b"b");
    let decoded = expect_decode_ok(&valid_literal);
    assert_eq!(
        decoded,
        vec![QpackFieldPlan::Literal {
            name: "a".to_string(),
            value: "b".to_string(),
        }]
    );

    let invalid_name_utf8 = literal_name_value_section(&[0xff], b"b");
    expect_invalid_frame(&invalid_name_utf8, "qpack string is not valid utf-8");

    let truncated_name = vec![FIELD_SECTION_PREFIX[0], FIELD_SECTION_PREFIX[1], 0x23, b'a'];
    expect_unexpected_eof(&truncated_name);

    let dynamic_post_base = vec![FIELD_SECTION_PREFIX[0], FIELD_SECTION_PREFIX[1], 0x00];
    expect_qpack_policy(
        &dynamic_post_base,
        "post-base/dynamic qpack line representations not allowed in static-only mode",
    );
}

fn literal_name_value_section(name: &[u8], value: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(FIELD_SECTION_PREFIX.len() + 2 + name.len() + value.len());
    buf.extend_from_slice(&FIELD_SECTION_PREFIX);
    push_short_string_literal(&mut buf, 0x20, name);
    push_short_string_literal(&mut buf, 0x00, value);
    buf
}

fn push_short_string_literal(buf: &mut Vec<u8>, representation_bits: u8, bytes: &[u8]) {
    assert!(
        bytes.len() <= 7,
        "short literal helper only supports 3-bit inline lengths"
    );
    buf.push(representation_bits | bytes.len() as u8);
    buf.extend_from_slice(bytes);
}

fn observe_decode_result(result: Result<Vec<QpackFieldPlan>, H3NativeError>) {
    match result {
        Ok(plans) => {
            let debug = format!("{plans:?}");
            assert!(!debug.is_empty(), "decoded plan debug should not be empty");
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

fn expect_decode_ok(input: &[u8]) -> Vec<QpackFieldPlan> {
    match qpack_decode_field_section(input, H3QpackMode::StaticOnly) {
        Ok(decoded) => decoded,
        Err(error) => panic!("expected valid qpack field section, got {error:?}"),
    }
}

fn expect_invalid_frame(input: &[u8], expected: &'static str) {
    match qpack_decode_field_section(input, H3QpackMode::StaticOnly) {
        Err(H3NativeError::InvalidFrame(message)) => {
            assert_eq!(message, expected);
        }
        Ok(decoded) => panic!("expected InvalidFrame({expected}), got {decoded:?}"),
        Err(error) => panic!("expected InvalidFrame({expected}), got {error:?}"),
    }
}

fn expect_unexpected_eof(input: &[u8]) {
    match qpack_decode_field_section(input, H3QpackMode::StaticOnly) {
        Err(H3NativeError::UnexpectedEof) => {}
        Ok(decoded) => panic!("expected UnexpectedEof, got {decoded:?}"),
        Err(error) => panic!("expected UnexpectedEof, got {error:?}"),
    }
}

fn expect_qpack_policy(input: &[u8], expected: &'static str) {
    match qpack_decode_field_section(input, H3QpackMode::StaticOnly) {
        Err(H3NativeError::QpackPolicy(message)) => {
            assert_eq!(message, expected);
        }
        Ok(decoded) => panic!("expected QpackPolicy({expected}), got {decoded:?}"),
        Err(error) => panic!("expected QpackPolicy({expected}), got {error:?}"),
    }
}
