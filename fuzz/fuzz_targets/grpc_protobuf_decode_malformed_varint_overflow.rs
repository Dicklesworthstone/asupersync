#![no_main]

//! Cargo-fuzz target focused on two specific malformed-input shapes
//! that `grpc_prost_codec_decode.rs` does not exercise directly:
//!
//!   1. **Malformed varints with > 10 continuation bytes.**
//!      A protobuf varint is at most 10 bytes (10 × 7 = 70 bits, enough
//!      to fit any `u64`). Encoding 11+ bytes with the high bit set
//!      every time is malformed: prost MUST reject it before reading
//!      past the 10-byte boundary, otherwise a hostile peer can stream
//!      gigabytes of `0xFF` bytes and the decoder will keep allocating
//!      working memory. The existing structure-aware target uses a
//!      well-formed `encode_varint` helper that never emits this shape.
//!
//!   2. **Embedded length-delimited fields claiming u32::MAX-class lengths.**
//!      A `tag | wire-type 2` followed by a declared length near
//!      `u32::MAX` must be rejected — either by the codec's
//!      `max_message_size` cap (which the outer frame already enforces)
//!      or by prost itself when the declared length exceeds the
//!      remaining buffer. A regression where the decoder pre-allocates
//!      a buffer of the declared length BEFORE comparing against the
//!      remaining input is a remote OOM.
//!
//! Both shapes are constructed via `Arbitrary`-derived selectors so
//! libFuzzer can hill-climb on the malformed-prefix length, varint
//! continuation count, and embedded-tag identity.
//!
//! Properties asserted per iteration:
//!
//!   - The decoder NEVER panics.
//!   - `Ok(_)` is allowed only when the configured `max_size` is
//!     larger than the input (the outer-cap path is honoured).
//!   - Malformed-varint inputs (11+ continuation bytes for a u64
//!     field) MUST surface as `Err(ProtobufError::DecodeError)` or
//!     `Err(ProtobufError::MessageTooLarge)`, not `Ok(_)` and not
//!     panic.
//!   - Embedded-length-overflow inputs (declared length > input
//!     remaining) MUST surface as `Err`, not `Ok(_)`, regardless of
//!     the outer cap.
//!
//! ```bash
//! cargo +nightly fuzz run grpc_protobuf_decode_malformed_varint_overflow \
//!     -- -max_total_time=120
//! ```

use arbitrary::Arbitrary;
use asupersync::bytes::Bytes;
use asupersync::grpc::Codec;
use asupersync::grpc::protobuf::{ProstCodec, ProtobufError};
use libfuzzer_sys::fuzz_target;

/// Per-iteration cap. Enough to fit a malformed-varint stream plus a
/// length-overflow envelope while keeping fuzz iterations sub-second.
const MAX_BUF: usize = 4 * 1024;
/// `max_size` configured on the codec. Smaller than MAX_BUF so the
/// MessageTooLarge path is reachable on adversarial inputs.
const CODEC_MAX_SIZE: usize = 2 * 1024;

#[derive(Clone, PartialEq, prost::Message)]
struct ProbeMessage {
    /// Field 1: a u64 — exercises the varint decoder.
    #[prost(uint64, tag = "1")]
    counter: u64,
    /// Field 2: bytes — exercises length-delimited decoding and the
    /// embedded-length overflow path.
    #[prost(bytes = "vec", tag = "2")]
    payload: Vec<u8>,
    /// Field 3: nested message — exercises the embedded-message
    /// length-overflow path with a recursive prost decoder.
    #[prost(message, optional, tag = "3")]
    nested: Option<NestedProbe>,
}

#[derive(Clone, PartialEq, prost::Message)]
struct NestedProbe {
    #[prost(string, tag = "1")]
    name: String,
}

#[derive(Arbitrary, Debug)]
enum MalformedShape {
    /// Build a wire stream that opens with the field-1 (counter) tag
    /// followed by `cont_count` continuation bytes (`0xFF`) and a
    /// terminator. `cont_count > 10` is malformed; the decoder MUST
    /// reject it.
    OverlongVarint { cont_count: u8, terminator: u8 },
    /// Build a length-delimited field-2 (payload) with a declared
    /// length near `u32::MAX`, but supply only a short tail. The
    /// decoder MUST reject before allocating `declared_len` bytes.
    PayloadLengthOverflow {
        /// `u32::MAX - bump` is the declared length. Small bump → near
        /// the rim; large bump → comfortably within usize range so
        /// libFuzzer can compare both.
        bump: u32,
        actual_tail: Vec<u8>,
    },
    /// Same overflow shape but on the embedded-message field (tag 3,
    /// wire type 2 → recursive prost decode). This stresses the
    /// nested-decode path independently of the outer payload bytes.
    NestedLengthOverflow { bump: u32, actual_tail: Vec<u8> },
    /// Sanity: a well-formed message with a u64 counter and a small
    /// payload. Used to verify the harness itself can produce Ok(_).
    WellFormed { counter: u64, payload: Vec<u8> },
}

fn encode_varint(mut value: u64, out: &mut Vec<u8>) {
    while value >= 0x80 {
        out.push((value as u8 & 0x7f) | 0x80);
        value >>= 7;
    }
    out.push(value as u8);
}

fn encode_key(tag: u32, wire_type: u8, out: &mut Vec<u8>) {
    encode_varint(((tag << 3) | u32::from(wire_type)) as u64, out);
}

fuzz_target!(|shape: MalformedShape| {
    let (wire, must_reject) = match shape {
        MalformedShape::OverlongVarint {
            cont_count,
            terminator,
        } => {
            let mut wire = Vec::new();
            // Tag for field 1 (counter, varint wire type 0).
            encode_key(1, 0, &mut wire);
            // Up to MAX_BUF/2 continuation bytes. `cont_count > 10`
            // is the malformed shape.
            let n = (cont_count as usize).min(MAX_BUF / 2);
            for _ in 0..n {
                wire.push(0xFF); // high bit set → continuation
            }
            wire.push(terminator);
            // Malformed iff we exceeded prost's varint-byte limit.
            // prost rejects at 10 bytes max for u64 fields.
            let must_reject = n >= 10;
            (wire, must_reject)
        }
        MalformedShape::PayloadLengthOverflow { bump, actual_tail } => {
            let mut wire = Vec::new();
            // Tag for field 2 (payload, length-delimited wire type 2).
            encode_key(2, 2, &mut wire);
            // Declared length near u32::MAX. Saturate-clamp so we
            // don't overflow varint encoding.
            let declared = u64::from(u32::MAX.saturating_sub(bump));
            encode_varint(declared, &mut wire);
            // Actually supply only a short tail — shorter than
            // `declared`. This is the overflow shape.
            let tail = actual_tail
                .iter()
                .copied()
                .take(MAX_BUF.saturating_sub(wire.len()))
                .collect::<Vec<_>>();
            wire.extend_from_slice(&tail);
            // Always must-reject when declared exceeds available
            // (which is virtually guaranteed given declared near u32::MAX
            // and tail bounded by MAX_BUF).
            let must_reject = (declared as usize) > tail.len();
            (wire, must_reject)
        }
        MalformedShape::NestedLengthOverflow { bump, actual_tail } => {
            let mut wire = Vec::new();
            // Tag for field 3 (nested message, length-delimited).
            encode_key(3, 2, &mut wire);
            let declared = u64::from(u32::MAX.saturating_sub(bump));
            encode_varint(declared, &mut wire);
            let tail = actual_tail
                .iter()
                .copied()
                .take(MAX_BUF.saturating_sub(wire.len()))
                .collect::<Vec<_>>();
            wire.extend_from_slice(&tail);
            let must_reject = (declared as usize) > tail.len();
            (wire, must_reject)
        }
        MalformedShape::WellFormed { counter, payload } => {
            let mut wire = Vec::new();
            // Field 1 (counter).
            encode_key(1, 0, &mut wire);
            encode_varint(counter, &mut wire);
            // Field 2 (payload), length-prefixed correctly.
            let payload = payload.into_iter().take(MAX_BUF / 2).collect::<Vec<_>>();
            encode_key(2, 2, &mut wire);
            encode_varint(payload.len() as u64, &mut wire);
            wire.extend_from_slice(&payload);
            (wire, false)
        }
    };

    if wire.len() > MAX_BUF {
        return;
    }

    let mut codec = ProstCodec::<ProbeMessage, ProbeMessage>::with_max_size(CODEC_MAX_SIZE);
    let bytes = Bytes::from(wire.clone());
    let result = codec.decode(&bytes);

    match &result {
        Ok(_decoded) => {
            // Property: Ok(_) is only acceptable when the input fit
            // within the configured cap AND the input was not
            // labelled must-reject.
            assert!(
                wire.len() <= CODEC_MAX_SIZE,
                "decode succeeded past configured max size: len={}, max={CODEC_MAX_SIZE}",
                wire.len(),
            );
            assert!(
                !must_reject,
                "decoder accepted a must-reject malformed input: len={}, wire-prefix={:?}",
                wire.len(),
                &wire[..wire.len().min(16)],
            );
        }
        Err(ProtobufError::DecodeError(_)) => {
            // Decoder rejected — typed error, no panic. ✓
        }
        Err(ProtobufError::MessageTooLarge { size, limit }) => {
            assert_eq!(
                *size,
                wire.len(),
                "MessageTooLarge size must match input length",
            );
            assert_eq!(
                *limit, CODEC_MAX_SIZE,
                "MessageTooLarge limit must match codec config",
            );
            assert!(
                wire.len() > CODEC_MAX_SIZE,
                "MessageTooLarge requires input > limit",
            );
        }
        Err(ProtobufError::EncodeError(_)) => {
            panic!("decode path must not surface EncodeError");
        }
    }
});
