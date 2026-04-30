//! Audit + regression test for `src/grpc/codec.rs` unknown-
//! encoding fallback behavior (tick #186).
//!
//! Operator's question: "verify unknown encoding fallback."
//!
//! gRPC Spec context (compression.md):
//!
//!   When a server receives a request with `grpc-encoding: <X>`
//!   for an encoding `X` it does not support, the spec mandates:
//!     1. The server responds with `Code::Unimplemented` AND
//!        sets `grpc-accept-encoding` to its supported list, so
//!        the client can retry with a known encoding.
//!     2. The server MUST NOT silently fall back to identity
//!        and try to decode the (compressed) message bytes —
//!        that would corrupt the payload.
//!
//! Audit findings:
//!
//!   (a) **Header-level: `from_header_value` returns `None`
//!       for unknown** (client.rs:39-45). The string parse
//!       layer rejects everything outside `identity`/`gzip`.
//!       Pinned in tick #178.
//!
//!   (b) **Codec-level fallback: identity-only.** A FramedCodec
//!       configured WITHOUT a decompressor (because the
//!       grpc-encoding header was unknown and the transport
//!       adapter installed no decompressor) handles uncompressed
//!       frames fine. Any compressed_flag=1 frame is rejected
//!       at codec.rs:535-543 with
//!       `GrpcError::compression("compressed frame received but
//!       no frame decompressor configured")`. Pinned in
//!       tick #176.
//!
//!   (c) **Codec-level rejection produces stream poison**
//!       (codec.rs:520-525, 537). Once a tampered frame
//!       arrives, every subsequent decode_message returns
//!       Err — no slip-past attempt by following with a
//!       clean uncompressed frame. Pinned in tick #176.
//!
//!   (d) **Combined with the transport-adapter contract**:
//!       a transport adapter that sees `grpc-encoding: zstd`
//!       and parses with `from_header_value` gets None;
//!       the spec-compliant action is to surface
//!       `Code::Unimplemented` with `grpc-accept-encoding`
//!       listing the server's actual support. The codec
//!       layer's contribution: even if the adapter
//!       INCORRECTLY proceeds without an Unimplemented
//!       rejection, the codec STILL refuses to decode
//!       compressed frames it can't honor. The
//!       defense-in-depth posture means the unknown-encoding
//!       fallback class can't accidentally accept compressed
//!       payloads as identity.
//!
//! Regression tests below pin (a)+(b)+(d) at the codec API
//! surface.

use asupersync::bytes::BytesMut;
use asupersync::codec::Decoder;
use asupersync::grpc::CompressionEncoding;
use asupersync::grpc::{FramedCodec, GrpcCodec, IdentityCodec};

const MESSAGE_HEADER_SIZE: usize = 5;

fn lpm_frame(compressed_flag: u8, declared_length: u32, body: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(MESSAGE_HEADER_SIZE + body.len());
    buf.push(compressed_flag);
    buf.extend_from_slice(&declared_length.to_be_bytes());
    buf.extend_from_slice(body);
    buf
}

#[test]
fn unknown_encoding_header_returns_none_at_parse_layer() {
    // Pin (a): the encoding parser rejects unknown strings.
    // This is the FIRST gate — a transport adapter that calls
    // from_header_value gets None and must decide what to do.
    // Spec-compliant action: respond with Code::Unimplemented.
    let unknown_encodings = ["zstd", "br", "deflate", "snappy", "lz4", "compress"];
    for enc in unknown_encodings {
        assert!(
            CompressionEncoding::from_header_value(enc).is_none(),
            "unknown encoding {enc:?} MUST return None — transport \
             adapter then surfaces Code::Unimplemented per spec",
        );
    }
}

#[test]
fn codec_without_decompressor_accepts_uncompressed_frames() {
    // Pin (b): when no decompressor is configured (the
    // unknown-encoding fallback state), uncompressed frames
    // (compressed_flag=0) decode normally — this is the
    // "identity-only" fallback.
    let mut codec: FramedCodec<IdentityCodec> = FramedCodec::new(IdentityCodec);
    let frame = lpm_frame(0, 5, b"hello");
    let mut buf = BytesMut::from(&frame[..]);

    let msg = codec
        .decode_message(&mut buf)
        .expect("uncompressed frame decodes")
        .expect("frame complete");
    assert_eq!(
        msg.as_ref(),
        b"hello",
        "identity-only fallback handles uncompressed frames correctly",
    );
}

#[test]
fn codec_without_decompressor_rejects_compressed_frames() {
    // Pin (b)+(d): the defense-in-depth property. Even if a
    // transport adapter forgot to surface Code::Unimplemented
    // for an unknown encoding header, the codec layer STILL
    // refuses to interpret a compressed frame as identity. The
    // peer cannot smuggle a compressed payload past the
    // identity-only fallback.
    let mut codec: FramedCodec<IdentityCodec> = FramedCodec::new(IdentityCodec);
    let frame = lpm_frame(1, 5, b"world");
    let mut buf = BytesMut::from(&frame[..]);

    let err = codec
        .decode_message(&mut buf)
        .expect_err("compressed frame without decompressor MUST reject");
    let err_str = format!("{err:?}");
    assert!(
        err_str.to_lowercase().contains("compress")
            || err_str.to_lowercase().contains("decompressor"),
        "rejection must surface as compression error; got {err_str}",
    );
}

#[test]
fn codec_poisoned_after_unknown_encoding_compressed_frame() {
    // Pin (c)+(d): the codec poisons after the rejection so a
    // peer can't follow with a clean frame. The "unknown
    // encoding then valid identity" attack pattern fails: even
    // the well-formed second frame returns Err.
    let mut codec: FramedCodec<IdentityCodec> = FramedCodec::new(IdentityCodec);
    let mut wire = BytesMut::new();
    // Frame 1: compressed (the unknown-encoding case).
    wire.extend_from_slice(&lpm_frame(1, 5, b"abcde"));
    // Frame 2: clean uncompressed.
    wire.extend_from_slice(&lpm_frame(0, 4, b"clean"[..4].try_into().unwrap()));

    let _ = codec
        .decode_message(&mut wire)
        .expect_err("first decode rejects");
    let err = codec
        .decode_message(&mut wire)
        .expect_err("post-poison rejects");
    let err_str = format!("{err:?}");
    assert!(
        err_str.to_lowercase().contains("poison")
            || err_str.to_lowercase().contains("protocol"),
        "post-poison error must mention poisoned state; got {err_str}",
    );
}

#[test]
fn unknown_encoding_at_framing_layer_does_not_panic() {
    // Pin: the framing layer (GrpcCodec::decode) processes the
    // raw LPM frame without consulting the encoding header
    // (encoding negotiation happens at the FramedCodec layer
    // above). A frame with compressed_flag=0 OR 1 reaches the
    // framing decode without panic; the framing decode just
    // returns the GrpcMessage with the flag bit preserved.
    //
    // Pinned: GrpcCodec::decode never panics on either flag,
    // never panics on missing decompressor (it doesn't have
    // one — that's FramedCodec's responsibility).
    let mut codec = GrpcCodec::with_max_size(64 * 1024);
    let compressed_frame = lpm_frame(1, 5, b"abcde");
    let mut buf = BytesMut::from(&compressed_frame[..]);
    let msg = codec
        .decode(&mut buf)
        .expect("framing decode succeeds")
        .expect("frame complete");
    assert!(msg.compressed, "compressed flag preserved in framing layer");
    assert_eq!(msg.data.as_ref(), b"abcde");
    // The decompression decision lives in FramedCodec, not
    // GrpcCodec — so a transport adapter that wraps GrpcCodec
    // without FramedCodec sees raw flagged frames and must
    // handle decompression itself.
}

#[test]
fn empty_compressed_flag_frame_without_decompressor_still_rejects() {
    // Pin (b)+(d) edge: an EMPTY compressed-flagged frame
    // (compressed_flag=1, length=0) STILL rejects without a
    // configured decompressor. A peer cannot bypass the
    // unknown-encoding fallback by sending an "empty
    // compressed" message that requires no actual
    // decompression.
    let mut codec: FramedCodec<IdentityCodec> = FramedCodec::new(IdentityCodec);
    let frame = lpm_frame(1, 0, b"");
    let mut buf = BytesMut::from(&frame[..]);

    let err = codec
        .decode_message(&mut buf)
        .expect_err("empty compressed frame rejects without decompressor");
    let err_str = format!("{err:?}");
    assert!(
        err_str.to_lowercase().contains("compress")
            || err_str.to_lowercase().contains("decompressor"),
        "empty-compressed rejection still compression-class; got {err_str}",
    );
}

#[test]
fn unknown_encoding_fallback_chain_at_known_attack_vectors() {
    // Pin (a)+(b)+(d) end-to-end story: every known unsupported
    // gRPC encoding follows the same fallback chain — header
    // parse rejects, transport adapter surfaces Unimplemented
    // (out of this audit's scope), codec layer rejects any
    // compressed frame.
    //
    // We pin the codec-side defense: a wide range of attack
    // strings all yield the same fallback (None at parse, no
    // decompressor at codec, compressed-frame reject).
    let attacks = [
        "zstd",
        "br",
        "deflate",
        "lzma",
        "xz",
        "snappy",
        "lz4",
        "compress",
        "BR",
        "Brotli",
        "ZsTd",
    ];
    for attack in attacks {
        // Layer 1: parse rejects.
        assert!(
            CompressionEncoding::from_header_value(attack).is_none(),
            "{attack:?} must reject at parse",
        );
        // Layer 2: codec without decompressor rejects compressed
        // frames (identity-only fallback). Pinned at the
        // FramedCodec level above; same instance, same Err.
    }
    // Layer 2 pin (single instance):
    let mut codec: FramedCodec<IdentityCodec> = FramedCodec::new(IdentityCodec);
    let frame = lpm_frame(1, 4, b"abcd");
    let mut buf = BytesMut::from(&frame[..]);
    assert!(codec.decode_message(&mut buf).is_err());
}
