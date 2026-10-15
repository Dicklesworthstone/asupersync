#![no_main]

//! Cargo-fuzz target for varint round-trip via `asupersync::grpc::ProstCodec`.
//!
//! `src/grpc/protobuf.rs::ProstCodec` does not contain its own varint
//! encoder — the varint encoding flows through prost's
//! `prost::Message::encode` for every protobuf-typed integer field
//! (uint64 / int64 / int32 / sint32 / sint64 / etc). This fuzzer
//! drives an `Arbitrary`-derived struct of integer fields covering
//! the varint and zigzag wire types, encodes via ProstCodec, decodes
//! back, and asserts:
//!
//!   1. **Round-trip identity for any (u64, i64, u32, i32) tuple**:
//!      encode(M) followed by decode produces M', M' == M for every
//!      value the type can hold — including u64::MAX (worst-case
//!      10-byte varint) and i64::MIN (worst-case zigzag).
//!
//!   2. **No malformed output**: the encoded bytes always decode
//!      cleanly back through prost's own decoder. A regression that
//!      emitted truncated varints or skipped continuation bits would
//!      produce decode errors here.
//!
//!   3. **No panic**: encode and decode never unwind for any input
//!      a `Arbitrary`-derived struct can construct.
//!
//! Why this fuzzer in addition to grpc_prost_codec_decode.rs:
//! that target focuses on adversarial DECODE bytes (malformed varints
//! coming off the wire); this target locks the ENCODE side's
//! never-malformed contract. A regression where ProstCodec emitted a
//! varint with the high bit set on the 10th byte (illegal — varint
//! payload is at most 10 bytes for u64) would slip past decode-side
//! fuzzing if the bug was symmetric (encode malformed → decode
//! accepts the malformed bytes).
//!
//! ```bash
//! cargo +nightly fuzz run grpc_protobuf_varint_round_trip -- -max_total_time=120
//! ```

use arbitrary::Arbitrary;
use asupersync::bytes::Bytes;
use asupersync::grpc::{Codec, ProstCodec};
use libfuzzer_sys::fuzz_target;

#[derive(Clone, PartialEq, prost::Message)]
struct VarintFixture {
    /// Plain varint.
    #[prost(uint64, tag = "1")]
    u_value: u64,
    /// Two's-complement varint (always 10 bytes for negatives).
    #[prost(int64, tag = "2")]
    i_value: i64,
    /// 32-bit varint.
    #[prost(uint32, tag = "3")]
    u32_value: u32,
    /// 32-bit two's-complement varint.
    #[prost(int32, tag = "4")]
    i32_value: i32,
    /// ZigZag varint — sign is interleaved with magnitude.
    #[prost(sint64, tag = "5")]
    zz64_value: i64,
    /// ZigZag 32-bit.
    #[prost(sint32, tag = "6")]
    zz32_value: i32,
    /// Repeated u64 — exercises the packed-varint encoding path
    /// where multiple varints land in one length-delimited chunk.
    #[prost(uint64, repeated, tag = "7")]
    u_seq: Vec<u64>,
}

#[derive(Arbitrary, Debug)]
struct FuzzInput {
    u_value: u64,
    i_value: i64,
    u32_value: u32,
    i32_value: i32,
    zz64_value: i64,
    zz32_value: i32,
    u_seq: Vec<u64>,
}

const MAX_REPEATED: usize = 64;

fuzz_target!(|input: FuzzInput| {
    let msg = VarintFixture {
        u_value: input.u_value,
        i_value: input.i_value,
        u32_value: input.u32_value,
        i32_value: input.i32_value,
        zz64_value: input.zz64_value,
        zz32_value: input.zz32_value,
        // Bound the repeated lane so each iteration stays sub-second.
        u_seq: input.u_seq.into_iter().take(MAX_REPEATED).collect(),
    };

    // Property 1 + 3: encode never panics, never errors for fixture-
    // sized payloads that fit within the codec's max_message_size.
    let mut codec = ProstCodec::<VarintFixture, VarintFixture>::new();
    let encoded = match codec.encode(&msg) {
        Ok(bytes) => bytes,
        // MessageTooLarge is legal for a fixture whose repeated lane
        // happens to overflow the cap; not a fuzz finding.
        Err(_) => return,
    };

    // Property 2: encoded bytes ALWAYS decode cleanly. A regression
    // where the encoder emitted a malformed varint (e.g. >10 bytes
    // with high bit set on every byte) would surface as a decode
    // error here.
    let decoded = codec
        .decode(&Bytes::from(encoded.to_vec()))
        .expect("self-encoded bytes must always round-trip cleanly");

    // Property 1 (final assert): the decoded message tree must equal
    // the original. A regression in any varint encoding lane (plain,
    // two's-complement, zigzag, packed-repeated, 32-bit vs 64-bit)
    // surfaces here as a field-by-field mismatch.
    assert_eq!(
        decoded, msg,
        "varint round-trip drift: original message != decoded",
    );

    // Specifically pin each field's round-trip so a regression in
    // ONE lane (e.g. zigzag) doesn't masquerade as a generic struct
    // diff.
    assert_eq!(decoded.u_value, msg.u_value, "u64 varint drift");
    assert_eq!(
        decoded.i_value, msg.i_value,
        "i64 two's-complement varint drift"
    );
    assert_eq!(decoded.u32_value, msg.u32_value, "u32 varint drift");
    assert_eq!(
        decoded.i32_value, msg.i32_value,
        "i32 two's-complement varint drift"
    );
    assert_eq!(decoded.zz64_value, msg.zz64_value, "sint64 zigzag drift");
    assert_eq!(decoded.zz32_value, msg.zz32_value, "sint32 zigzag drift");
    assert_eq!(
        decoded.u_seq, msg.u_seq,
        "repeated uint64 (packed varint) drift"
    );
});
