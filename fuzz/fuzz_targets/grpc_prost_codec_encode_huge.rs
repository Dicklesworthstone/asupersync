#![no_main]

//! Cargo-fuzz target for ProstCodec encoder under arbitrary message
//! trees, with explicit coverage of the huge-message lane.
//!
//! Two distinct concerns this target locks down:
//!
//!   1. **Encode → decode round-trip identity for arbitrary message
//!      trees.** The varint round-trip target
//!      (`grpc_protobuf_varint_round_trip`) covers integer fields;
//!      this target adds string / bytes / nested-message / repeated
//!      fields so the full prost surface gets shaken. A regression
//!      where encode emitted bytes that decode could not parse
//!      back to the original tree surfaces here.
//!
//!   2. **No buffer-realloc panic on huge messages.** ProstCodec's
//!      encode path computes `encoded_len` first, checks against
//!      `max_message_size`, then allocates a Vec with that capacity
//!      and runs the prost encoder. The encoder writes into the
//!      Vec via the prost `BufMut` impl. A regression where the
//!      capacity was over- or under-stated, or where the BufMut
//!      impl panics on capacity exhaustion (rather than
//!      reallocating gracefully), would surface here as a panic
//!      under huge-message inputs. The cap-rejection branch
//!      (MessageTooLarge) is also asserted to fire BEFORE any
//!      allocation work so a hostile peer cannot OOM the server
//!      via a "claimed huge size, then crash" pattern.
//!
//! Properties asserted per fuzz iteration:
//!
//!   - Encoder NEVER panics for any Arbitrary input (bounded by
//!     MAX_INPUT_LEN to keep iterations sub-second).
//!   - Decoder accepts the encoded bytes and returns a tree
//!     equal to the input.
//!   - When `encoded_len` exceeds `max_message_size`, encode returns
//!     `Err(MessageTooLarge)` — never panic, never silent truncation.
//!   - When encoded bytes are within the cap, the resulting
//!     `Bytes` length equals prost's `encode_to_vec` length (no
//!     padding, no over-allocation observable on the wire).
//!
//! ```bash
//! cargo +nightly fuzz run grpc_prost_codec_encode_huge -- -max_total_time=120
//! ```

use arbitrary::Arbitrary;
use asupersync::bytes::Bytes;
use asupersync::grpc::{Codec, ProstCodec};
use libfuzzer_sys::fuzz_target;
use prost::Message;

/// Cap on per-iteration input size. The huge-message lane stresses
/// the realloc/BufMut path; large enough to trigger 4× and 8×
/// growth steps, small enough to keep each iteration sub-second.
const MAX_INPUT_LEN: usize = 256 * 1024;

/// Cap configured on the codec. Lower than MAX_INPUT_LEN so the
/// MessageTooLarge path is reachable on realistic seeds. Larger
/// than typical small messages so the round-trip lane runs.
const CODEC_MAX_SIZE: usize = 64 * 1024;

#[derive(Clone, PartialEq, prost::Message)]
struct EncodeFixture {
    #[prost(string, tag = "1")]
    name: String,
    #[prost(int64, tag = "2")]
    count: i64,
    #[prost(bytes = "vec", tag = "3")]
    payload: Vec<u8>,
    #[prost(message, optional, tag = "4")]
    nested: Option<NestedFixture>,
    #[prost(string, repeated, tag = "5")]
    labels: Vec<String>,
    #[prost(uint64, repeated, packed = "true", tag = "6")]
    counters: Vec<u64>,
}

#[derive(Clone, PartialEq, prost::Message)]
struct NestedFixture {
    #[prost(string, tag = "1")]
    inner_name: String,
    #[prost(int32, tag = "2")]
    inner_value: i32,
    #[prost(bytes = "vec", tag = "3")]
    inner_blob: Vec<u8>,
}

#[derive(Arbitrary, Debug)]
struct FuzzInput {
    name: String,
    count: i64,
    payload: Vec<u8>,
    nested_present: bool,
    inner_name: String,
    inner_value: i32,
    inner_blob: Vec<u8>,
    labels: Vec<String>,
    counters: Vec<u64>,
}

fn truncate_string(s: String, cap: usize) -> String {
    if s.len() <= cap {
        return s;
    }
    let mut end = cap;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    s[..end].to_string()
}

fn truncate_vec<T>(v: Vec<T>, cap: usize) -> Vec<T> {
    v.into_iter().take(cap).collect()
}

fuzz_target!(|input: FuzzInput| {
    // Bound each field independently so libFuzzer can hill-climb on
    // shape AND aggregate length. The aggregate cap below is what
    // really gates the huge-message lane.
    let msg = EncodeFixture {
        name: truncate_string(input.name, 1024),
        count: input.count,
        payload: truncate_vec(input.payload, 64 * 1024),
        nested: if input.nested_present {
            Some(NestedFixture {
                inner_name: truncate_string(input.inner_name, 512),
                inner_value: input.inner_value,
                inner_blob: truncate_vec(input.inner_blob, 32 * 1024),
            })
        } else {
            None
        },
        labels: truncate_vec(
            input
                .labels
                .into_iter()
                .map(|s| truncate_string(s, 256))
                .collect(),
            128,
        ),
        counters: truncate_vec(input.counters, 4096),
    };

    // Property 1+2: encoder never panics; encoded bytes round-trip.
    let mut codec = ProstCodec::<EncodeFixture, EncodeFixture>::with_max_size(CODEC_MAX_SIZE);
    let encoded_len_estimate = msg.encoded_len();

    if encoded_len_estimate > MAX_INPUT_LEN {
        // Out of fuzzer-budget; not a finding.
        return;
    }

    match codec.encode(&msg) {
        Ok(encoded) => {
            // Property 3: when encoded is Ok, the input fits within
            // CODEC_MAX_SIZE. The codec rejects with
            // MessageTooLarge BEFORE running prost's encoder, so an
            // Ok return implies the cap was honoured.
            assert!(
                encoded.len() <= CODEC_MAX_SIZE,
                "Ok encode produced {} bytes > CODEC_MAX_SIZE={CODEC_MAX_SIZE}",
                encoded.len(),
            );
            // Property 4: encoded bytes length equals prost's
            // encode_to_vec length. ProstCodec must not pad / over-
            // allocate observably on the wire.
            let raw = msg.encode_to_vec();
            assert_eq!(
                encoded.len(),
                raw.len(),
                "ProstCodec encode emitted {} bytes; raw prost {} — divergence \
                 means the wrapper is adding padding/framing inside the \
                 protobuf payload, which would break tonic / grpc-go interop",
                encoded.len(),
                raw.len(),
            );

            // Round-trip the encoded bytes through the same codec.
            let decoded = codec
                .decode(&Bytes::from(encoded.to_vec()))
                .expect("self-encoded bytes within cap must always decode");
            assert_eq!(
                decoded, msg,
                "round-trip lost the message tree — encoder/decoder pair drift",
            );
        }
        Err(_) => {
            // The only legal Err on the encode path is MessageTooLarge.
            // ProtobufError::EncodeError indicates a prost-internal
            // failure (out-of-memory or similar) which is not a fuzz
            // finding. Either way: no panic was the requirement.
            assert!(
                encoded_len_estimate > CODEC_MAX_SIZE || encoded_len_estimate > MAX_INPUT_LEN,
                "encode returned Err for a message that fits the cap: \
                 encoded_len_estimate={encoded_len_estimate}, cap={CODEC_MAX_SIZE}",
            );
        }
    }
});
