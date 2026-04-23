//! grpc-web trailer encode/decode round-trip oracle.
//!
//! The existing fuzz_grpc_web_framing target is a strong crash-only harness.
//! It does not assert that `decode_trailers(encode_trailers(status, meta))`
//! recovers the input exactly — a silent divergence in percent-encoding of
//! CR/LF, base64 round-trip of binary metadata, or header-block key
//! normalization would slip past a crash oracle.
//!
//! This target is Archetype 2 (round-trip) focused on the trailer frame:
//!
//!   1. encode_trailers(status, metadata) into BytesMut
//!   2. decode_trailers(body) of the 5-byte-header-stripped payload
//!   3. assert recovered status.code and status.message match
//!   4. assert every ASCII metadata entry is present with the same value
//!   5. assert every binary metadata entry is present with bytewise-equal value
//!
//! Keys and values are constrained to a conservative ASCII range so
//! Metadata::insert cannot reject them up-front; CR/LF is explicitly NOT
//! filtered so the percent-encoding path at web.rs:113 is exercised.

#![no_main]

use arbitrary::Arbitrary;
use asupersync::bytes::{Bytes, BytesMut};
use asupersync::grpc::status::{Code, Status};
use asupersync::grpc::streaming::{Metadata, MetadataValue};
use asupersync::grpc::web::{decode_trailers, encode_trailers};
use libfuzzer_sys::fuzz_target;

const MAX_METADATA: usize = 8;
const MAX_KEY: usize = 32;
const MAX_VALUE: usize = 128;
const MAX_MESSAGE: usize = 256;

#[derive(Arbitrary, Debug)]
struct AsciiEntry {
    key: String,
    value: String,
}

#[derive(Arbitrary, Debug)]
struct BinEntry {
    key: String,
    value: Vec<u8>,
}

#[derive(Arbitrary, Debug)]
struct Case {
    status_code: i32,
    message: String,
    ascii: Vec<AsciiEntry>,
    binary: Vec<BinEntry>,
}

/// Restrict key chars to gRPC-valid set: lowercase ASCII + digits + `-`/`_`.
/// Empty keys are rejected by Metadata::insert; drop them.
fn canonicalize_key(raw: &str, for_bin: bool) -> Option<String> {
    let mut key: String = raw
        .chars()
        .filter(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == '-' || *c == '_')
        .take(MAX_KEY)
        .collect();
    if key.is_empty() {
        return None;
    }
    // Strip any explicit -bin suffix so we control the variant.
    while key.ends_with("-bin") {
        key.truncate(key.len() - 4);
        if key.is_empty() {
            return None;
        }
    }
    if for_bin {
        key.push_str("-bin");
    }
    Some(key)
}

/// Restrict ASCII value chars to printable (visible) plus space — still
/// permits CR/LF only when we deliberately inject them elsewhere, keeping
/// the base oracle tractable.
fn canonicalize_ascii_value(raw: &str) -> String {
    raw.chars()
        .filter(|c| matches!(*c, ' '..='~'))
        .take(MAX_VALUE)
        .collect()
}

fuzz_target!(|case: Case| {
    let status = Status::new(
        Code::from_i32(case.status_code),
        case.message.chars().take(MAX_MESSAGE).collect::<String>(),
    );

    let mut metadata = Metadata::new();

    // Deterministic insertion order: ascii first, then binary; bound counts.
    for entry in case.ascii.iter().take(MAX_METADATA) {
        let Some(key) = canonicalize_key(&entry.key, false) else {
            continue;
        };
        let value = canonicalize_ascii_value(&entry.value);
        let _ = metadata.insert(key, value);
    }
    for entry in case.binary.iter().take(MAX_METADATA) {
        let Some(key) = canonicalize_key(&entry.key, true) else {
            continue;
        };
        let truncated = entry.value.iter().copied().take(MAX_VALUE).collect::<Vec<u8>>();
        let _ = metadata.insert_bin(key, Bytes::from(truncated));
    }

    // ---- Encode ----
    let mut wire = BytesMut::new();
    encode_trailers(&status, &metadata, &mut wire);

    // Strip the 5-byte framing header: [flag][u32 length].
    assert!(wire.len() >= 5, "encoded trailer is shorter than 5-byte header");
    let flag = wire[0];
    assert_eq!(flag & 0x80, 0x80, "trailer frame must have MSB set");
    let declared_len = u32::from_be_bytes([wire[1], wire[2], wire[3], wire[4]]) as usize;
    assert_eq!(
        wire.len() - 5,
        declared_len,
        "declared payload length must equal actual payload bytes",
    );
    let payload = &wire[5..];

    // ---- Decode ----
    let Ok(decoded) = decode_trailers(payload) else {
        // A failed decode on our own encode is a real bug — but keep crash-only
        // posture for the rare case of encoder emitting a header block the
        // decoder tightens later. Surface via an explicit assert rather than
        // silently returning.
        panic!(
            "decode_trailers rejected our own encode_trailers output (code={:?}, \
             message={:?}, wire_len={})",
            status.code(),
            status.message(),
            wire.len(),
        );
    };

    // ---- Property: status round-trips exactly ----
    assert_eq!(
        decoded.status.code(),
        status.code(),
        "status code round-trip diverged",
    );
    assert_eq!(
        decoded.status.message(),
        status.message(),
        "status message round-trip diverged",
    );

    // ---- Property: every input metadata entry is recoverable ----
    // Metadata::insert may reject or deduplicate keys; iterate the
    // post-insert snapshot rather than the user's raw lists so the
    // assertion corresponds to what was actually encoded.
    for (key, value) in metadata.iter() {
        let got = decoded.metadata.get(key).unwrap_or_else(|| {
            panic!("metadata key {key:?} missing after round-trip")
        });
        match (value, got) {
            (MetadataValue::Ascii(original), MetadataValue::Ascii(round)) => {
                assert_eq!(
                    original, round,
                    "ASCII metadata value for {key:?} diverged after round-trip",
                );
            }
            (MetadataValue::Binary(original), MetadataValue::Binary(round)) => {
                assert_eq!(
                    original.as_ref(),
                    round.as_ref(),
                    "Binary metadata value for {key:?} diverged after round-trip",
                );
            }
            (orig, got) => panic!(
                "metadata variant flipped for {key:?}: encoded {orig:?}, decoded {got:?}",
            ),
        }
    }
});
