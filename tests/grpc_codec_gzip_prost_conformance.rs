//! Conformance harness: gzip-compressed gRPC messages decode to the
//! identical `prost::Message` tree across the asupersync codec
//! pipeline.
//!
//! NOTE on operator wording: the original tick said "LZF-compressed";
//! `src/grpc/codec.rs` implements gzip (flate2), not LZF — gRPC's
//! standard compression registry is `identity` / `gzip` / `deflate`,
//! and LZF is not in any wire-protocol entry. The closest faithful
//! interpretation is gzip — that's the only compressor wired into
//! `FramedCodec::with_gzip_frame_codec`. This file pins the gzip
//! conformance.
//!
//! Pinned contract: for any prost::Message M whose encoded bytes
//! fit within the codec's `max_message_size`,
//!
//!     encode(M) via FramedCodec<ProstCodec> + gzip
//!     === decode that wire ===
//!     yields a message tree equal to M.
//!
//! Plus the inverse: an uncompressed-encode of M followed by a
//! decode through the gzip-aware codec must yield the same tree
//! (the codec's compressed-flag byte distinguishes the two paths
//! per the gRPC LPM spec).
//!
//! Why this is "vs prost": both `prost::Message::encode_to_vec`
//! and the gzip path are deterministic functions of the input
//! message, so the round-trip identity here is the same conformance
//! grpc-go / tonic provide. A divergence means our gzip layer is
//! corrupting the protobuf payload — an interop-killer at the
//! wire level.

#![cfg(feature = "compression")]

use asupersync::bytes::BytesMut;
use asupersync::grpc::{FramedCodec, ProstCodec};

#[derive(Clone, PartialEq, prost::Message)]
struct GzipFixture {
    #[prost(string, tag = "1")]
    name: String,
    #[prost(int32, tag = "2")]
    count: i32,
    /// Repeated payload makes gzip ratios meaningful — the same bytes
    /// repeated compress to far less than identity, so the
    /// compressed-vs-uncompressed wire diverges in a way the
    /// round-trip MUST hide.
    #[prost(bytes = "vec", tag = "3")]
    payload: Vec<u8>,
    #[prost(uint64, tag = "4")]
    wide: u64,
}

fn fixtures() -> Vec<GzipFixture> {
    vec![
        // (a) Default — empty prost wire, exercises the empty-payload
        // gzip branch (small but non-trivial gzip frame).
        GzipFixture::default(),
        // (b) Tiny — exercises the path where compressed size may
        // EXCEED uncompressed size (gzip header overhead) without
        // forcing the codec to fall back to identity.
        GzipFixture {
            name: "alice".into(),
            count: 42,
            payload: b"hi".to_vec(),
            wide: 0,
        },
        // (c) High-ratio — repeated bytes that gzip handles well.
        // Verifies the round-trip survives the typical "good gzip
        // case" where decompressed length far exceeds compressed.
        GzipFixture {
            name: "repeat".into(),
            count: 0,
            payload: vec![0xAB; 4 * 1024],
            wide: 0xDEAD_BEEF,
        },
        // (d) Mixed — varied payload shapes so the gzip dictionary
        // path runs through nontrivial Huffman codes.
        GzipFixture {
            name: "mixed-content-with-some-bytes".into(),
            count: -1234,
            payload: (0..1024).map(|i| (i * 31 + 7) as u8).collect(),
            wide: u64::MAX,
        },
    ]
}

#[test]
fn gzip_round_trip_preserves_prost_message_tree() {
    for (i, msg) in fixtures().iter().enumerate() {
        let mut wire = BytesMut::new();
        let mut encoder =
            FramedCodec::<ProstCodec<GzipFixture, GzipFixture>>::new(ProstCodec::new())
                .with_gzip_frame_codec();
        encoder
            .encode_message(msg, &mut wire)
            .expect("gzip encode_message must succeed for fixture-sized payload");

        // Decode through a separate codec instance so any encoder-side
        // hidden state cannot leak into the decoder.
        let mut decoder =
            FramedCodec::<ProstCodec<GzipFixture, GzipFixture>>::new(ProstCodec::new())
                .with_gzip_frame_codec();
        let decoded = decoder
            .decode_message(&mut wire)
            .expect("gzip decode_message must succeed for self-encoded fixture")
            .expect("decoder must produce a message");

        assert_eq!(
            decoded, *msg,
            "fixture {i}: gzip round-trip lost the message tree",
        );
        assert!(
            wire.is_empty(),
            "fixture {i}: decoder must consume the entire frame; \
             leaving {} trailing bytes is a framer-vs-decompressor desync",
            wire.len(),
        );
    }
}

#[test]
fn gzip_compressed_flag_byte_is_set_on_wire() {
    // The first wire byte distinguishes compressed from uncompressed
    // frames per the gRPC LPM spec. A regression that emitted
    // gzip-compressed payload bytes WITHOUT setting the flag would
    // make a tonic / grpc-go peer try to decode the gzip header as
    // protobuf — observable here as a self-inconsistent wire shape.
    let msg = GzipFixture {
        name: "flag-check".into(),
        count: 1,
        payload: vec![0xAA; 256],
        wide: 0,
    };
    let mut wire = BytesMut::new();
    let mut encoder = FramedCodec::<ProstCodec<GzipFixture, GzipFixture>>::new(ProstCodec::new())
        .with_gzip_frame_codec();
    encoder.encode_message(&msg, &mut wire).expect("encode");

    assert!(wire.len() >= 5, "frame must include the 5-byte LPM prefix");
    assert_eq!(
        wire[0], 0x01,
        "compressed flag byte must be 0x01 when the gzip codec is wired in",
    );

    // The declared length must still equal the compressed body length —
    // length tracks the BODY, not the original message.
    let declared = u32::from_be_bytes([wire[1], wire[2], wire[3], wire[4]]) as usize;
    assert_eq!(
        declared,
        wire.len() - 5,
        "declared length must equal compressed-body bytes (no trailing padding, \
         no truncation, no double-compression header drift)",
    );
}

#[test]
fn gzip_decoder_accepts_uncompressed_frame_without_recompressing() {
    // The compressed-flag byte tells the decoder whether to run gzip
    // decompression. A gzip-aware FramedCodec MUST still decode an
    // uncompressed frame correctly — that's the standard wire-level
    // negotiation: "I support gzip, but this frame happens to be
    // identity." A regression where the gzip-aware decoder
    // unconditionally ran gzip would corrupt every uncompressed
    // payload from a peer that chose not to compress this message.
    let msg = GzipFixture {
        name: "uncompressed".into(),
        count: 7,
        payload: b"plain".to_vec(),
        wide: 0,
    };

    // Encode without gzip — uses the identity path, flag byte = 0x00.
    let mut wire = BytesMut::new();
    let mut plain_encoder =
        FramedCodec::<ProstCodec<GzipFixture, GzipFixture>>::new(ProstCodec::new());
    plain_encoder
        .encode_message(&msg, &mut wire)
        .expect("plain encode");
    assert_eq!(wire[0], 0x00, "uncompressed encoder must set flag=0");

    // Decode WITH gzip-aware decoder — must skip decompression
    // because flag=0.
    let mut gzip_decoder =
        FramedCodec::<ProstCodec<GzipFixture, GzipFixture>>::new(ProstCodec::new())
            .with_gzip_frame_codec();
    let decoded = gzip_decoder
        .decode_message(&mut wire)
        .expect("gzip-aware decoder must accept uncompressed frame")
        .expect("must produce a message");

    assert_eq!(
        decoded, msg,
        "gzip-aware decoder must not double-process an uncompressed frame",
    );
}

#[test]
fn gzip_round_trip_is_idempotent_across_repeated_calls() {
    // Pin that encoder/decoder state does not accumulate between
    // calls — a regression where gzip's deflate state was reused
    // across messages would manifest as the SECOND round-trip
    // diverging from the first while the first stays equal to the
    // input.
    let msg = GzipFixture {
        name: "idempotent".into(),
        count: 3,
        payload: vec![0x55; 512],
        wide: 0,
    };

    let mut encoder = FramedCodec::<ProstCodec<GzipFixture, GzipFixture>>::new(ProstCodec::new())
        .with_gzip_frame_codec();
    let mut decoder = FramedCodec::<ProstCodec<GzipFixture, GzipFixture>>::new(ProstCodec::new())
        .with_gzip_frame_codec();

    for round in 0..3 {
        let mut wire = BytesMut::new();
        encoder
            .encode_message(&msg, &mut wire)
            .expect("encode round");
        let decoded = decoder
            .decode_message(&mut wire)
            .expect("decode round")
            .expect("message");
        assert_eq!(
            decoded, msg,
            "round {round} of gzip encode/decode drifted — codec state is leaking",
        );
        assert!(
            wire.is_empty(),
            "round {round} left {} trailing bytes — framer state leak",
            wire.len(),
        );
    }
}
