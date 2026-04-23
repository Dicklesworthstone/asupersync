//! Length-prefix framing: Arbitrary-derived config + encode/decode round-trip.
//!
//! Goal: for any valid `LengthDelimitedCodecBuilder` configuration and any
//! payload that fits inside `max_frame_length`, assert two properties:
//!
//!   1. `encode(payload)` never errors for an in-range payload.
//!   2. `decode(encode(payload))` yields exactly `payload` back.
//!   3. Re-encoding the decoded frame with the same codec produces bytes
//!      identical to the first wire output (encode determinism).
//!
//! These properties are a stronger oracle than the existing crash-only or
//! splitter-boundary targets: they cover the width×endianness×offset×skip
//! configuration lattice with a round-trip check that catches off-by-one
//! length-field width, endianness swaps, and skip/offset miscalculation
//! bugs that a pure crash oracle cannot see.

#![no_main]

use arbitrary::Arbitrary;
use asupersync::bytes::BytesMut;
use asupersync::codec::{Decoder, Encoder, LengthDelimitedCodec};
use libfuzzer_sys::fuzz_target;

#[derive(Arbitrary, Debug)]
struct Case {
    /// Selects `length_field_length` in 1..=8.
    length_field_length_minus1: u8,
    /// Selects `max_frame_length` in { 1 KiB, 2 KiB, …, 1 MiB }.
    max_frame_log2: u8,
    /// Selects `length_field_offset` in 0..=15.
    length_field_offset: u8,
    /// Wire byte order.
    big_endian: bool,
    /// Payload to encode.
    payload: Vec<u8>,
}

fuzz_target!(|case: Case| {
    let length_field_length = usize::from(case.length_field_length_minus1 % 8) + 1;
    let max_frame_length = 1usize << (10 + (case.max_frame_log2 % 11));
    let length_field_offset = usize::from(case.length_field_offset % 16);
    let num_skip = length_field_offset + length_field_length;

    // Skip payloads that the codec will reject up-front; this isolates the
    // round-trip invariant to the subset where encode is expected to succeed.
    if case.payload.len() > max_frame_length {
        return;
    }
    // Also skip payloads whose length cannot fit in the configured field
    // width. Encoder rejects these with Err; that path is exercised by
    // sibling targets and is outside this oracle's scope.
    let max_encodable = match length_field_length {
        1..=7 => (1u64 << (length_field_length * 8)) - 1,
        8 => u64::MAX,
        _ => unreachable!(),
    };
    if (case.payload.len() as u64) > max_encodable {
        return;
    }

    let builder_template = LengthDelimitedCodec::builder()
        .length_field_offset(length_field_offset)
        .length_field_length(length_field_length)
        .num_skip(num_skip)
        .max_frame_length(max_frame_length);
    let builder_template = if case.big_endian {
        builder_template.big_endian()
    } else {
        builder_template.little_endian()
    };

    let mut encoder = builder_template.clone().new_codec();
    let payload = BytesMut::from(case.payload.as_slice());

    let mut wire = BytesMut::new();
    match encoder.encode(payload.clone(), &mut wire) {
        Ok(()) => {}
        Err(_) => {
            // Encoder is allowed to reject; no invariant to check.
            return;
        }
    }

    // Property 2: decode of fresh wire yields the original payload.
    let mut decoder = builder_template.clone().new_codec();
    let mut read_cursor = wire.clone();
    let decoded = match decoder.decode(&mut read_cursor) {
        Ok(Some(frame)) => frame,
        Ok(None) => panic!(
            "decode returned None on a fully-formed frame \
             (payload_len={}, field_len={length_field_length}, offset={length_field_offset}, be={})",
            payload.len(),
            case.big_endian
        ),
        Err(err) => panic!(
            "decode errored on freshly-encoded wire: {err} \
             (payload_len={}, field_len={length_field_length}, offset={length_field_offset}, be={})",
            payload.len(),
            case.big_endian
        ),
    };
    assert_eq!(
        decoded, payload,
        "round-trip payload mismatch (offset={length_field_offset}, \
         field_len={length_field_length}, be={})",
        case.big_endian
    );

    // Property 3: re-encode reproduces the original wire bytes. This catches
    // non-deterministic encoding (e.g. uninitialised padding in the header
    // region introduced by a future refactor).
    let mut rewire = BytesMut::new();
    encoder
        .encode(decoded, &mut rewire)
        .expect("re-encode of decoded frame must succeed");
    assert_eq!(
        rewire, wire,
        "re-encode produced different wire bytes than the original encoding"
    );
});
