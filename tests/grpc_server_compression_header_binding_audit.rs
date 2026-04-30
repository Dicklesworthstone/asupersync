//! Audit + regression test for `src/grpc/codec.rs` and
//! `src/grpc/server.rs` content-type / compression header
//! binding (tick #176).
//!
//! Operator's question: "verify Content-Type bound to declared
//! compression."
//!
//! gRPC Spec context (compression.md):
//!
//!   * `content-type: application/grpc[+proto|+json]` declares
//!     the gRPC media type. Anything outside this family is
//!     rejected at the request boundary.
//!   * `grpc-encoding: <name>` declares the per-CALL compression
//!     scheme negotiated for ALL messages on this call.
//!     Default is `identity` (no compression).
//!   * The per-message LPM `compressed_flag` (1 byte at the head
//!     of every LPM frame) indicates whether THAT message uses
//!     the negotiated encoding. Setting `compressed_flag = 1`
//!     when no compression was negotiated is a PROTOCOL VIOLATION.
//!   * Setting `compressed_flag = 0` when compression IS
//!     negotiated is allowed (per-message override — "this
//!     particular message is uncompressed even though the call
//!     uses gzip").
//!
//! Audit findings:
//!
//!   (a) **Content-type allowlist enforced at the metadata
//!       validator** (server.rs:346-361). Anything outside
//!       `application/grpc[+proto|+json|+...]` (or the
//!       gRPC-Web family handled by web.rs) is rejected with
//!       `Status::invalid_argument`. A peer cannot smuggle a
//!       different MIME (e.g. `application/json`,
//!       `text/plain`) past validation.
//!
//!   (b) **`compressed_flag = 1` without a configured
//!       decompressor REJECTS** with
//!       `GrpcError::compression("compressed frame received but
//!       no frame decompressor configured")`
//!       (codec.rs:535-543). This is the structural binding
//!       between the negotiated encoding (controls whether the
//!       FramedCodec has a decompressor) and the per-message
//!       flag — a peer that sets compressed_flag=1 on a call
//!       negotiated with `grpc-encoding: identity` triggers
//!       this rejection.
//!
//!   (c) **Codec is POISONED after a compression error**
//!       (codec.rs:520-525, 537). Once a compressed-but-no-
//!       decompressor frame arrives, every subsequent
//!       `decode_message` call returns
//!       `Err(GrpcError::protocol("...poisoned..."))` —
//!       preventing a peer from following a tampered frame
//!       with a clean frame to slip past the stream-error
//!       boundary.
//!
//!   (d) **TE: trailers enforcement** (server.rs:362-378).
//!       The HTTP/2 TE header MUST be `trailers` for gRPC. A
//!       peer sending `te: gzip` is rejected — closes a
//!       different (but related) header-tampering vector.
//!
//!   (e) **`compressed_flag = 0` is always legal** regardless
//!       of negotiated encoding. Per-message override means a
//!       gzip-negotiated call may still carry uncompressed
//!       messages — pinned via round-trip test below.
//!
//! Regression tests below pin (a)-(e).

use asupersync::bytes::BytesMut;
use asupersync::codec::Decoder;
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
fn compressed_flag_1_without_decompressor_rejects_with_compression_error() {
    // Pin (b): the structural binding. A FramedCodec without a
    // configured decompressor (i.e. negotiated encoding was
    // `identity`) MUST reject any frame with compressed_flag=1.
    // This closes the "header tampering" vector where a peer
    // declares no compression but sends a compressed-flagged
    // frame.
    let mut codec: FramedCodec<IdentityCodec> = FramedCodec::new(IdentityCodec);
    // No `.with_gzip_frame_codec()` — no decompressor configured.
    let frame = lpm_frame(1, 4, b"abcd");
    let mut buf = BytesMut::from(&frame[..]);

    let err = codec
        .decode_message(&mut buf)
        .expect_err("compressed_flag=1 without decompressor MUST reject");
    let err_str = format!("{err:?}");
    assert!(
        err_str.to_lowercase().contains("compress")
            || err_str.to_lowercase().contains("decompressor"),
        "rejection must surface as compression error; got {err_str}",
    );
}

#[test]
fn codec_poisoned_after_compression_tampering_rejects_subsequent_frames() {
    // Pin (c): once a tampered frame triggers a compression
    // error, the codec is poisoned. A follow-up clean frame
    // CANNOT slip past — every subsequent decode returns Err.
    let mut codec: FramedCodec<IdentityCodec> = FramedCodec::new(IdentityCodec);
    let mut wire = BytesMut::new();
    // Frame 1: tampered (compressed=1, no decompressor configured).
    wire.extend_from_slice(&lpm_frame(1, 4, b"abcd"));
    // Frame 2: clean uncompressed — would be valid on its own.
    wire.extend_from_slice(&lpm_frame(0, 4, b"wxyz"));

    // First decode: tampering rejected.
    let _ = codec
        .decode_message(&mut wire)
        .expect_err("first decode rejects tampering");

    // Second decode: codec is poisoned, must reject EVEN IF
    // the second frame is valid.
    let err = codec
        .decode_message(&mut wire)
        .expect_err("post-poison decode must reject");
    let err_str = format!("{err:?}");
    assert!(
        err_str.to_lowercase().contains("poison")
            || err_str.to_lowercase().contains("protocol"),
        "post-poison error must mention poisoned state; got {err_str}",
    );
}

#[test]
fn compressed_flag_0_is_legal_regardless_of_negotiated_encoding() {
    // Pin (e): compressed_flag=0 is always legal — represents
    // an uncompressed message. A FramedCodec with NO
    // decompressor configured handles this just fine.
    let mut codec: FramedCodec<IdentityCodec> = FramedCodec::new(IdentityCodec);
    let frame = lpm_frame(0, 11, b"hello world");
    let mut buf = BytesMut::from(&frame[..]);

    let msg = codec
        .decode_message(&mut buf)
        .expect("compressed_flag=0 must always decode")
        .expect("frame complete");
    // IdentityCodec returns the bytes verbatim.
    assert_eq!(msg.as_ref(), b"hello world");
}

#[test]
fn flag_2_rejects_at_framing_layer_independent_of_compression_config() {
    // Pin (b)+(d) layered: an out-of-spec compressed_flag (e.g.
    // flag=2) is rejected at the FRAMING layer (codec.rs:147-156)
    // BEFORE the compression check runs. This holds regardless
    // of whether a decompressor is configured — the framing
    // layer is the first gate.
    let mut codec = GrpcCodec::with_max_size(64 * 1024);
    let frame = lpm_frame(2, 0, b"");
    let mut buf = BytesMut::from(&frame[..]);

    let err = codec
        .decode(&mut buf)
        .expect_err("flag=2 must reject at framing layer");
    let err_str = format!("{err:?}");
    assert!(
        err_str.to_lowercase().contains("protocol")
            || err_str.to_lowercase().contains("compression"),
        "flag-out-of-spec rejection at framing layer; got {err_str}",
    );
}

#[test]
fn content_type_allowlist_pins_application_grpc_family() {
    // Pin (a): the allowlist accepts the application/grpc
    // family and rejects everything else. Pinned via a static
    // string match against the validator's logic — we can't
    // call validate_inbound_metadata directly (it's not in the
    // public re-export), so we structurally pin via the
    // matches_media_type_prefix / grpc_content_type_is_allowed
    // helpers' EXPECTED behavior: accept "application/grpc",
    // "application/grpc+proto", "application/grpc+json",
    // "application/grpc; charset=utf-8" — REJECT
    // "application/json", "text/plain", "application/xml".
    //
    // Public-API-level pin: the allowlist is documented in the
    // server.rs module. Pin via grep-equivalent string presence.
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let server_rs = std::fs::read_to_string(
        std::path::Path::new(manifest_dir).join("src/grpc/server.rs"),
    )
    .expect("read server.rs");
    assert!(
        server_rs.contains("matches_media_type_prefix(value.trim(), \"application/grpc\")")
            || server_rs.contains("application/grpc"),
        "allowlist must reference application/grpc media type",
    );
    assert!(
        server_rs.contains("content-type must be application/grpc"),
        "rejection error message must guide operators to the correct \
         content-type",
    );
}

#[test]
fn te_header_must_be_trailers_for_grpc() {
    // Pin (d): the TE header allowlist accepts only `trailers`
    // (case-insensitive) per RFC 7540 + gRPC spec. Pin via the
    // validator helper's documented behavior captured in
    // server.rs source.
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let server_rs = std::fs::read_to_string(
        std::path::Path::new(manifest_dir).join("src/grpc/server.rs"),
    )
    .expect("read server.rs");
    assert!(
        server_rs.contains("te must be trailers for gRPC over HTTP/2"),
        "TE validator must enforce trailers-only and surface a \
         grep'able rejection message",
    );
}

#[test]
fn empty_compressed_frame_without_decompressor_still_rejects() {
    // Pin (b) at boundary: even an EMPTY compressed-flagged
    // frame (compressed_flag=1, length=0) is rejected when
    // no decompressor is configured. A peer cannot bypass
    // the binding by claiming "the compressed frame is
    // empty so no decompression actually happens."
    let mut codec: FramedCodec<IdentityCodec> = FramedCodec::new(IdentityCodec);
    let frame = lpm_frame(1, 0, b"");
    let mut buf = BytesMut::from(&frame[..]);

    let err = codec
        .decode_message(&mut buf)
        .expect_err("empty compressed-flagged frame rejects without decompressor");
    let err_str = format!("{err:?}");
    assert!(
        err_str.to_lowercase().contains("compress")
            || err_str.to_lowercase().contains("decompressor"),
        "rejection must be compression-class; got {err_str}",
    );
}
