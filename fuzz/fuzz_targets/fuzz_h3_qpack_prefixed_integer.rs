//! br-asupersync-xt60rb: focused fuzz target for the QPACK prefixed-integer
//! decoder in `src/http/h3_native.rs::qpack_decode_prefixed_int`.
//!
//! The function is file-private but every call into it lives behind the
//! public [`qpack_decode_field_section`] entry point — every QPACK header
//! block on the wire walks through prefixed-int decoding for the field-
//! section preamble (Required Insert Count, Sign+DeltaBase) AND for every
//! indexed/literal representation prefix. We feed arbitrary bytes into
//! that public entry point and assert the decoder NEVER panics, never OOMs,
//! and never spins forever.
//!
//! Attack surface (all reachable from a malicious peer):
//!   * Truncated continuation chains
//!   * Overlarge shift values that approach the `checked_shl` boundary
//!   * `prefix_len` boundary (1..=8) — the entry point exercises this via
//!     the QPACK encoding spec (5-bit prefix for indexed/static, 4/3-bit
//!     prefixes for various literal forms)
//!   * Continuation chains exceeding the 9-byte cap (`shift > 56` guard)
//!
//! The harness must never panic. Decoder errors are expected — the
//! fail signal is a process abort, OOM, or hang.
//!
//! Run with: `cargo +nightly fuzz run fuzz_h3_qpack_prefixed_integer`

#![no_main]

use arbitrary::Arbitrary;
use asupersync::http::h3_native::{H3QpackMode, qpack_decode_field_section};
use libfuzzer_sys::fuzz_target;

/// Cap input size so libFuzzer doesn't waste cycles on multi-MB blobs that
/// the decoder would reject up-front.
const MAX_INPUT_BYTES: usize = 64 * 1024;

#[derive(Arbitrary, Debug)]
enum Scenario {
    /// Raw arbitrary bytes — the broadest coverage of prefix + continuation
    /// shapes. libFuzzer's coverage-guided mutation finds the interesting
    /// continuations on its own.
    Arbitrary(Vec<u8>),

    /// Continuation-chain shape: header block starts with a saturated 5-bit
    /// prefix (so `value < max_in_prefix` is false and the loop runs) and
    /// then attacker-controlled continuation bytes.
    SaturatedPrefixWithContinuation {
        /// Prefix byte to seed the input with — high bits are the
        /// representation tag, low 5 bits are forced to 0x1F (max-in-prefix)
        /// so the decoder enters its continuation loop.
        prefix_high_bits: u8,
        /// 0..=64 continuation bytes — the harness caps to prevent libFuzzer
        /// from exploring multi-MB inputs.
        continuation: Vec<u8>,
        /// Optional trailing bytes to make the section non-empty after the
        /// integer; lets the decoder advance past the int and exercise
        /// downstream paths.
        trailing: Vec<u8>,
    },

    /// All-`0x80` continuation chain — overflow / shift-cap guard test.
    /// `qpack_decode_prefixed_int` caps `shift` at 56 and returns
    /// `InvalidFrame` past that point; we want to confirm no path past
    /// the guard can panic.
    AllContinuation {
        prefix_byte: u8,
        /// Number of `0x80` continuations to emit (0..=128). The harness
        /// truncates to keep input bounded.
        count: u8,
    },
}

fuzz_target!(|s: Scenario| match s {
    Scenario::Arbitrary(bytes) => fuzz_arbitrary(&bytes),
    Scenario::SaturatedPrefixWithContinuation {
        prefix_high_bits,
        continuation,
        trailing,
    } => fuzz_saturated_prefix(prefix_high_bits, &continuation, &trailing),
    Scenario::AllContinuation { prefix_byte, count } => fuzz_all_continuation(prefix_byte, count),
});

fn fuzz_arbitrary(bytes: &[u8]) {
    if bytes.len() > MAX_INPUT_BYTES {
        return;
    }
    let _ = qpack_decode_field_section(bytes, H3QpackMode::StaticOnly);
}

fn fuzz_saturated_prefix(prefix_high_bits: u8, continuation: &[u8], trailing: &[u8]) {
    // 5-bit prefix saturated to 0x1F; high 3 bits drawn from the fuzzer.
    let prefix = (prefix_high_bits & 0xE0) | 0x1F;

    let cont_take = continuation.len().min(64);
    let trail_take = trailing.len().min(MAX_INPUT_BYTES - 1 - cont_take);

    let mut buf = Vec::with_capacity(1 + cont_take + trail_take);
    buf.push(prefix);
    buf.extend_from_slice(&continuation[..cont_take]);
    buf.extend_from_slice(&trailing[..trail_take]);

    let _ = qpack_decode_field_section(&buf, H3QpackMode::StaticOnly);
}

fn fuzz_all_continuation(prefix_byte: u8, count: u8) {
    // Saturate the 5-bit prefix so the continuation loop runs.
    let prefix = (prefix_byte & 0xE0) | 0x1F;
    let count = count.min(128) as usize;

    let mut buf = Vec::with_capacity(1 + count + 1);
    buf.push(prefix);
    // Long run of `0x80`-flagged bytes (continuation continues forever
    // — the decoder must terminate via its `shift > 56` guard).
    for _ in 0..count {
        buf.push(0x80);
    }
    // Final byte without the continuation bit — gives the decoder a chance
    // to terminate cleanly if it didn't already error out via the shift cap.
    buf.push(0x00);

    let _ = qpack_decode_field_section(&buf, H3QpackMode::StaticOnly);
}
