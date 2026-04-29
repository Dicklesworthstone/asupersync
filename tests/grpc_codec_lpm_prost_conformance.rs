//! Conformance harness: gRPC Length-Prefixed Message (LPM) framing of a
//! `prost::Message` payload produces byte-identical wire frames to the
//! manual specification — the 5-byte prefix (1-byte compressed flag +
//! 4-byte big-endian u32 length) followed by the raw
//! `Message::encode_to_vec()` payload.
//!
//! Pins the contract that `FramedCodec<ProstCodec<T, T>>::encode_message`
//! is exactly:
//!
//! ```text
//!     wire = [0x00] || BE_U32(prost_bytes.len()) || prost_bytes
//!     where prost_bytes = M.encode_to_vec()
//! ```
//!
//! and that the wire is therefore byte-identical to what a tonic /
//! grpc-go peer would produce for the SAME message — both
//! implementations build LPM the same way on top of prost. A regression
//! that, e.g., flipped the compressed flag default, swapped
//! endianness, or invisibly added padding bytes between the prefix and
//! payload would surface here as a 1-bit / 1-byte byte-vector
//! mismatch, before any cross-implementation interop test gets a
//! chance to fail in a hard-to-debug way.
//!
//! What this file does NOT cover (out of scope, separate beads):
//!   * Compression: `tests/grpc_codec_golden.rs::golden_grpc_codec_gzip_*`
//!     pins gzip frame layout.
//!   * Bare framing (without prost): the sibling
//!     `tests/grpc_codec_golden.rs::golden_grpc_codec_length_prefixed_messages`
//!     locks the framing of arbitrary raw bytes.
//!   * The decode path: `tests/grpc_codec_prost_conformance.rs` already
//!     pins ProstCodec round-trip equivalence with raw prost.

use asupersync::bytes::BytesMut;
use asupersync::grpc::{FramedCodec, ProstCodec};
use prost::Message;

/// Conformance fixture: a varied-shape protobuf message so any
/// regression that perturbs the encoded byte stream surfaces in the
/// frame-byte comparison.
#[derive(Clone, PartialEq, prost::Message)]
struct LpmFixture {
    #[prost(string, tag = "1")]
    name: String,
    #[prost(int32, tag = "2")]
    count: i32,
    #[prost(bytes = "vec", tag = "3")]
    payload: Vec<u8>,
    #[prost(uint64, tag = "4")]
    wide: u64,
}

fn fixtures() -> Vec<LpmFixture> {
    vec![
        // (a) Default — the empty-bytes case. wire is 5 bytes total
        // (prefix only).
        LpmFixture::default(),
        // (b) Tiny — single small string field.
        LpmFixture {
            name: "alice".into(),
            count: 0,
            payload: vec![],
            wide: 0,
        },
        // (c) All fields present — exercises every wire-type slot.
        LpmFixture {
            name: "everything".into(),
            count: -42,
            payload: b"hello-payload".to_vec(),
            wide: 0xCAFE_BABE_DEAD_BEEF,
        },
        // (d) Big payload — checks that the BE u32 length encodes
        // multi-byte values correctly and the framer doesn't truncate
        // at byte boundaries it didn't intend.
        LpmFixture {
            name: "large".into(),
            count: 1234,
            payload: (0..1024).map(|i| (i % 251) as u8).collect(),
            wide: u64::MAX,
        },
    ]
}

/// Manually assemble the spec-prescribed LPM frame for an
/// already-encoded protobuf payload. This is the oracle: a faithful
/// reading of the gRPC HTTP/2 framing spec without going through the
/// asupersync codec.
fn build_lpm_oracle(prost_bytes: &[u8]) -> Vec<u8> {
    let mut wire = Vec::with_capacity(5 + prost_bytes.len());
    wire.push(0x00); // compressed flag = 0 (uncompressed)
    let len = u32::try_from(prost_bytes.len()).expect("fixture length fits in u32");
    wire.extend_from_slice(&len.to_be_bytes());
    wire.extend_from_slice(prost_bytes);
    wire
}

#[test]
fn framed_codec_lpm_matches_manual_oracle_byte_for_byte() {
    for (i, msg) in fixtures().iter().enumerate() {
        let prost_bytes = msg.encode_to_vec();
        let oracle = build_lpm_oracle(&prost_bytes);

        let mut codec_wire = BytesMut::with_capacity(oracle.len());
        let mut codec = FramedCodec::<ProstCodec<LpmFixture, LpmFixture>>::new(ProstCodec::new());
        codec
            .encode_message(msg, &mut codec_wire)
            .expect("encode_message must succeed for fixture-sized payload");

        assert_eq!(
            codec_wire.as_ref(),
            oracle.as_slice(),
            "fixture {i}: FramedCodec<ProstCodec> must produce byte-identical LPM \
             to the manual spec oracle. A divergence here means the wrapper introduces \
             a transform that no tonic / grpc-go peer expects.",
        );
    }
}

#[test]
fn framed_codec_lpm_prefix_layout_is_canonical() {
    // Stricter slice-by-slice assertions on the prefix shape so a
    // future regression that, e.g., emits the length in little-endian
    // (or shifts the compressed flag to a different byte) surfaces
    // with a self-explanatory message rather than a generic
    // bytes-not-equal diff.
    for (i, msg) in fixtures().iter().enumerate() {
        let prost_bytes = msg.encode_to_vec();
        let mut wire = BytesMut::with_capacity(5 + prost_bytes.len());
        let mut codec = FramedCodec::<ProstCodec<LpmFixture, LpmFixture>>::new(ProstCodec::new());
        codec.encode_message(msg, &mut wire).expect("encode");

        assert!(
            wire.len() >= 5,
            "fixture {i}: every LPM frame must include the 5-byte prefix",
        );
        assert_eq!(
            wire[0], 0x00,
            "fixture {i}: compressed flag byte must default to 0 (uncompressed)",
        );
        let declared_len = u32::from_be_bytes([wire[1], wire[2], wire[3], wire[4]]);
        assert_eq!(
            declared_len as usize,
            prost_bytes.len(),
            "fixture {i}: BE u32 length prefix must equal prost.encode_to_vec().len() \
             (got declared={declared_len}, expected={})",
            prost_bytes.len(),
        );
        assert_eq!(
            wire.len() - 5,
            prost_bytes.len(),
            "fixture {i}: payload region length must equal declared length \
             (no trailing padding, no truncation)",
        );
        assert_eq!(
            &wire[5..],
            prost_bytes.as_slice(),
            "fixture {i}: payload region must be byte-identical to prost.encode_to_vec()",
        );
    }
}

#[test]
fn framed_codec_lpm_default_message_is_exactly_five_bytes() {
    // The conformance corner that catches the largest set of off-by-
    // one and accidental-padding bugs: a default-valued message has
    // an empty prost encoding, so the entire wire frame must be
    // exactly 5 bytes (the prefix) and the declared length must be 0.
    let msg = LpmFixture::default();
    let mut wire = BytesMut::new();
    let mut codec = FramedCodec::<ProstCodec<LpmFixture, LpmFixture>>::new(ProstCodec::new());
    codec.encode_message(&msg, &mut wire).expect("encode");

    assert_eq!(
        wire.len(),
        5,
        "default-valued LpmFixture has zero prost bytes so the entire LPM frame \
         must be exactly 5 bytes (the prefix)",
    );
    assert_eq!(
        &wire[..],
        &[0x00, 0x00, 0x00, 0x00, 0x00],
        "default-valued LPM frame must be the canonical 5 zero bytes",
    );
}
