//! Conformance harness: `asupersync::grpc::protobuf::ProstCodec` vs the
//! raw `prost::Message` API.
//!
//! `ProstCodec` is a thin wrapper that adds a size cap on top of prost's
//! own encode/decode (see `src/grpc/protobuf.rs`). The conformance
//! relation is therefore:
//!
//!     for any message M whose encoded length fits within the cap,
//!         ProstCodec::encode(M)  ==  M.encode_to_vec()
//!         ProstCodec::decode(B)  ==  T::decode(B)        (when B fits)
//!
//! A divergence here means the wrapper is silently mutating the wire
//! shape — every layer downstream (gRPC framing, gRPC-Web, the
//! distributed-trace evidence ledger) treats the wrapper output as
//! authoritative protobuf, so any drift is a cross-component breakage.
//!
//! What this file does NOT cover (out of scope, separate bead lanes):
//!   * Fuzz-driven malformed-input behavior — `fuzz/fuzz_targets/grpc_protobuf_decode_*`.
//!   * gRPC framing layer (length-prefix + compressed flag) — that's
//!     `GrpcCodec`, tested elsewhere.
//!   * Compression — covered by `grpc_gzip_message_decode.rs` and the
//!     gzip fuzz target.

use asupersync::bytes::Bytes;
use asupersync::grpc::Codec;
use asupersync::grpc::protobuf::ProstCodec;
use prost::Message;

/// Message with the type spread the conformance relation must hold for:
///   - varint-encoded integers (string field length, int32, uint64)
///   - length-delimited bytes
///   - a nested message (recursive prost decode)
///   - a repeated field (multiple wire entries, same tag)
///   - a sint64 (zigzag-encoded varint)
#[derive(Clone, PartialEq, prost::Message)]
struct ConformanceMessage {
    #[prost(string, tag = "1")]
    name: String,
    #[prost(int32, tag = "2")]
    count: i32,
    #[prost(bytes = "vec", tag = "3")]
    payload: Vec<u8>,
    #[prost(message, optional, tag = "4")]
    nested: Option<NestedMessage>,
    #[prost(string, repeated, tag = "5")]
    labels: Vec<String>,
    #[prost(uint64, tag = "6")]
    wide_count: u64,
    #[prost(sint64, tag = "7")]
    zigzag: i64,
}

#[derive(Clone, PartialEq, prost::Message)]
struct NestedMessage {
    #[prost(string, tag = "1")]
    inner_name: String,
    #[prost(int32, tag = "2")]
    inner_value: i32,
}

/// Returns the canonical fixture set. Each element exercises a
/// different shape so a regression in any one wire-form path surfaces.
fn fixtures() -> Vec<ConformanceMessage> {
    vec![
        // (1) Default message — every field at its default. Wire form
        // must be the empty byte sequence on the prost side; the
        // wrapper must not inject any framing.
        ConformanceMessage::default(),
        // (2) String + int + bytes — the simple case.
        ConformanceMessage {
            name: "alice".into(),
            count: 42,
            payload: b"hello world".to_vec(),
            nested: None,
            labels: vec![],
            wide_count: 0,
            zigzag: 0,
        },
        // (3) Nested message — recursive prost decode through the
        // wrapper.
        ConformanceMessage {
            name: "outer".into(),
            count: 1,
            payload: vec![],
            nested: Some(NestedMessage {
                inner_name: "inner".into(),
                inner_value: -7,
            }),
            labels: vec![],
            wide_count: 0,
            zigzag: 0,
        },
        // (4) Repeated field — packed/non-packed, same tag emitted
        // multiple times. Order must be preserved through the
        // wrapper round-trip.
        ConformanceMessage {
            name: "tags".into(),
            count: 3,
            payload: vec![],
            nested: None,
            labels: vec!["a".into(), "bb".into(), "ccc".into()],
            wide_count: 0,
            zigzag: 0,
        },
        // (5) Numeric corners — u64::MAX and i64::MIN exercise the
        // varint / zigzag encoders at their endpoints.
        ConformanceMessage {
            name: "edge".into(),
            count: i32::MIN,
            payload: vec![],
            nested: None,
            labels: vec![],
            wide_count: u64::MAX,
            zigzag: i64::MIN,
        },
        // (6) Larger payload + everything-set. Combined fixture
        // catches encoder ordering bugs that only surface when many
        // tags are emitted in one message.
        ConformanceMessage {
            name: "all".repeat(10),
            count: 100_000,
            payload: (0..512).map(|i| (i % 251) as u8).collect(),
            nested: Some(NestedMessage {
                inner_name: "nested-inside".into(),
                inner_value: 1234,
            }),
            labels: (0..16).map(|i| format!("label-{i:03}")).collect(),
            wide_count: 0xFEED_FACE_CAFE_BABE,
            zigzag: 1_234_567_890_123_456,
        },
    ]
}

#[test]
fn prost_codec_encode_matches_raw_prost_byte_for_byte() {
    for (i, msg) in fixtures().iter().enumerate() {
        let raw_bytes = msg.encode_to_vec();
        let mut codec = ProstCodec::<ConformanceMessage, ConformanceMessage>::new();
        let codec_bytes = codec
            .encode(msg)
            .expect("ProstCodec::encode should succeed for fixture within cap")
            .to_vec();
        assert_eq!(
            codec_bytes, raw_bytes,
            "fixture {i}: ProstCodec::encode must produce byte-identical output to \
             prost::Message::encode_to_vec — the wrapper introduces a transform that \
             would silently break every downstream consumer of the wire bytes",
        );
    }
}

#[test]
fn prost_codec_decode_matches_raw_prost_message_tree() {
    for (i, msg) in fixtures().iter().enumerate() {
        let wire = msg.encode_to_vec();

        // Decode via raw prost.
        let raw_decoded = ConformanceMessage::decode(wire.as_slice())
            .expect("raw prost decode of self-encoded message should succeed");

        // Decode via ProstCodec.
        let mut codec = ProstCodec::<ConformanceMessage, ConformanceMessage>::new();
        let codec_decoded = codec
            .decode(&Bytes::from(wire.clone()))
            .expect("ProstCodec::decode should succeed for fixture within cap");

        assert_eq!(
            codec_decoded, raw_decoded,
            "fixture {i}: ProstCodec::decode and prost::Message::decode must converge on \
             the same message tree for the same wire bytes",
        );
        assert_eq!(
            codec_decoded, *msg,
            "fixture {i}: round-trip via ProstCodec must be the identity on the message",
        );
    }
}

#[test]
fn cross_implementation_round_trip_is_stable() {
    // Compose the four directions: encode-via-wrapper / decode-via-raw
    // and encode-via-raw / decode-via-wrapper. All four MUST land on
    // the same message tree. A divergence in any cell would mean one
    // implementation was lossy or non-canonical.
    for (i, msg) in fixtures().iter().enumerate() {
        let mut codec = ProstCodec::<ConformanceMessage, ConformanceMessage>::new();

        let wrapped_bytes = codec.encode(msg).expect("wrapped encode").to_vec();
        let raw_bytes = msg.encode_to_vec();

        let from_wrapped_via_raw = ConformanceMessage::decode(wrapped_bytes.as_slice())
            .expect("raw decode of wrapped bytes");
        let from_raw_via_wrapped = codec
            .decode(&Bytes::from(raw_bytes.clone()))
            .expect("wrapped decode of raw bytes");

        assert_eq!(
            from_wrapped_via_raw, *msg,
            "fixture {i}: wrapped-encode → raw-decode must round-trip to identity",
        );
        assert_eq!(
            from_raw_via_wrapped, *msg,
            "fixture {i}: raw-encode → wrapped-decode must round-trip to identity",
        );
        assert_eq!(
            from_wrapped_via_raw, from_raw_via_wrapped,
            "fixture {i}: cross-implementation decoded trees must converge",
        );
    }
}

#[test]
fn empty_wire_decodes_to_default_in_both_implementations() {
    // Sanity: an empty wire byte-stream is the canonical encoding of a
    // default-valued message. Both implementations must produce the
    // same default — a non-default result here would mean the wrapper
    // was injecting hidden state.
    let mut codec = ProstCodec::<ConformanceMessage, ConformanceMessage>::new();
    let wrapped = codec
        .decode(&Bytes::new())
        .expect("ProstCodec must accept empty wire");
    let raw = ConformanceMessage::decode(&[][..])
        .expect("prost must accept empty wire as default message");
    assert_eq!(wrapped, ConformanceMessage::default());
    assert_eq!(wrapped, raw);
}
