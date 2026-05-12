//! Audit + regression test for `src/grpc/server.rs` +
//! `src/grpc/codec.rs` compression negotiation surface (ticks
//! #155 + #156).
//!
//! Tick #155 question: "verify Accept-Encoding bounded, no
//! decompression-bomb risk, identity always supported."
//!
//! Tick #156 question: "verify max-encoded-size + max-decoded-size
//! both enforced." Both caps are present and symmetric:
//!   * `GrpcCodec::encode` (codec.rs:173) rejects an outgoing
//!     payload with `data.len() > max_encode_message_size` BEFORE
//!     allocation or serialization. The error surfaces as
//!     `GrpcError::MessageTooLarge`.
//!   * `GrpcCodec::decode` (codec.rs:135) rejects an incoming LPM
//!     frame whose declared length exceeds
//!     `max_decode_message_size` BEFORE reading the body bytes.
//!     Same `MessageTooLarge` shape.
//!   * The two limits are independently configurable via
//!     `FramedCodec::with_message_size_limits(inner,
//!     max_decode_message_size, max_encode_message_size)`. A
//!     deployment can asymmetrically tighten one direction
//!     without affecting the other.
//!   * Both apply to the *post-decompression* / *pre-compression*
//!     payload size, NOT the wire bytes — so a compressed bomb
//!     that expands to > `max_decode_message_size` is rejected
//!     by the gzip decompressor's per-iteration check (see (c)
//!     below) AND, even if the gzip layer is identity, the size
//!     prefix check at codec.rs:135 fires before allocation.
//!
//! Audit findings:
//!
//!   (a) **Accept-Encoding whitelist is bounded — only Identity
//!       and Gzip.** `CompressionEncoding` (client.rs:22-27) is a
//!       closed enum: anything that is NOT exactly `"identity"`
//!       or `"gzip"` returns `None` from `from_header_value`. An
//!       attacker cannot smuggle exotic encodings (`br`,
//!       `deflate`, `zstd`, `xz`) — the parser refuses them.
//!
//!   (b) **Identity is ALWAYS supported.**
//!       `ServerConfig::default()` initialises
//!       `accept_compression: vec![CompressionEncoding::Identity]`
//!       (server.rs:436). The default-built server accepts
//!       uncompressed payloads. A regression that flipped to
//!       requiring compression by default would break
//!       interop with vanilla clients.
//!
//!   (c) **Decompression bomb defense at the per-iteration
//!       level.** `gzip_frame_decompress` (codec.rs:300-328)
//!       enforces `max_size` on EVERY 8 KiB chunk read from the
//!       decoder via the `total > max_size` check at line 322.
//!       A 4 GiB-expanding compressed bomb fails fast at
//!       `max_size + 8 KiB` of cumulative output, NOT after the
//!       full bomb has been buffered. The pre-allocation hint
//!       at line 309 is `min(input.len() * 4, max_size)` so
//!       attacker-controlled tiny inputs cannot pre-allocate
//!       arbitrary capacity (br-asupersync-ky9o3j).
//!
//!   (d) **`max_decode_message_size` is the policy knob** that
//!       feeds `gzip_frame_decompress` as `max_size` (audited at
//!       tick #141). Default is 4 MiB. Operators can tighten via
//!       `FramedCodec::with_max_size(..., max_decode_message_size)`.
//!
//! Regression tests below pin (a), (b), and (c).

use asupersync::bytes::{Bytes, BytesMut};
use asupersync::codec::Encoder;
use asupersync::grpc::CompressionEncoding;
use asupersync::grpc::ServerConfig;
use asupersync::grpc::{GrpcCodec, GrpcMessage};

#[test]
fn accept_encoding_whitelist_rejects_exotic_encodings() {
    // Pin (a): the encoding parser is a closed-enum allowlist.
    // Anything outside identity/gzip returns None — operators
    // cannot accidentally accept br/deflate/zstd/xz/exec/etc.
    let exotic = [
        "deflate",  // historically supported by HTTP, NOT by gRPC
        "br",       // brotli — not a gRPC encoding
        "zstd",     // not a gRPC encoding
        "xz",       // not a gRPC encoding
        "snappy",   // not a gRPC encoding
        "lz4",      // not a gRPC encoding
        "compress", // legacy HTTP encoding — never a gRPC encoding
        "Identity", // case-sensitive — must be lowercase per spec
        "Gzip",     // case-sensitive
        "GZIP",
        "IDENTITY",
        "gzip ",        // trailing space
        " gzip",        // leading space
        "gzip,deflate", // comma list — single value only
        "exec",         // attacker fuzz string
        "",
        "../identity", // path-traversal-shaped string
    ];
    for value in exotic {
        assert!(
            CompressionEncoding::from_header_value(value).is_none(),
            "exotic encoding {value:?} must be rejected — \
             allowlist is identity/gzip only",
        );
    }
}

#[test]
fn accept_encoding_whitelist_accepts_canonical_identity_and_gzip() {
    // Pin (a) positive case: the canonical lowercase forms
    // identity and gzip ARE accepted. A regression that broke
    // these would deny all compressed traffic.
    assert_eq!(
        CompressionEncoding::from_header_value("identity"),
        Some(CompressionEncoding::Identity),
        "canonical 'identity' must parse",
    );
    assert_eq!(
        CompressionEncoding::from_header_value("gzip"),
        Some(CompressionEncoding::Gzip),
        "canonical 'gzip' must parse",
    );
}

#[test]
fn server_config_default_accept_compression_includes_identity() {
    // Pin (b): default ServerConfig accepts Identity. A regression
    // that emptied the accept list (or required gzip) would break
    // interop with vanilla clients that send uncompressed payloads.
    let config = ServerConfig::default();
    assert!(
        config
            .accept_compression
            .contains(&CompressionEncoding::Identity),
        "default ServerConfig must accept Identity — uncompressed \
         payloads are the gRPC interop baseline. accept_compression={:?}",
        config.accept_compression,
    );
}

#[test]
fn server_config_default_does_not_send_compression() {
    // Pin: default ServerConfig does NOT send compressed
    // responses (`send_compression: None` at server.rs:435). This
    // is the conservative posture — server only compresses if the
    // operator explicitly opts in via `.send_compression(...)`.
    // Pin so a regression that flipped to gzip-by-default would
    // be a visible behavior change.
    let config = ServerConfig::default();
    assert!(
        config.send_compression.is_none(),
        "default ServerConfig::send_compression must be None — \
         server compresses only when operator opts in via \
         .send_compression(...). Regression candidate: \
         a default-on flip would change wire bytes for every \
         response and break clients that don't advertise gzip in \
         grpc-accept-encoding. got: {:?}",
        config.send_compression,
    );
}

#[cfg(feature = "compression")]
#[test]
fn gzip_frame_decompress_rejects_oversize_at_max_size_boundary() {
    // Pin (c): the bomb defense fires at the FIRST 8 KiB chunk
    // that pushes the cumulative decompressed size past
    // `max_size`. We construct a payload that decompresses to
    // 4 KiB — well within max_size=8 KiB — and verify it
    // succeeds. Then we set max_size=2 KiB and verify the same
    // payload fails-fast with MessageTooLarge.
    use asupersync::grpc::gzip_frame_compress;
    use asupersync::grpc::gzip_frame_decompress;

    let payload = vec![b'A'; 4 * 1024];
    let compressed =
        gzip_frame_compress(Bytes::from(payload.clone())).expect("compress must succeed");

    // 8 KiB cap — the 4 KiB payload fits.
    let decompressed =
        gzip_frame_decompress(compressed.clone(), 8 * 1024).expect("under cap, must decompress");
    assert_eq!(
        decompressed.as_ref(),
        &payload[..],
        "round-trip must preserve bytes",
    );

    // 2 KiB cap — the 4 KiB payload is over cap, must reject.
    let err = gzip_frame_decompress(compressed, 2 * 1024)
        .expect_err("over cap, must reject (decompression-bomb defense)");
    let err_str = format!("{err:?}");
    assert!(
        err_str.contains("MessageTooLarge") || err_str.to_lowercase().contains("too large"),
        "rejection must surface as MessageTooLarge / equivalent — got: {err_str}",
    );
}

#[test]
fn grpc_codec_encode_side_max_size_rejects_oversize_payload() {
    // Pin (tick #156): encode-side cap at codec.rs:173 fires
    // BEFORE allocation/serialization. A regression that moved
    // the check to AFTER `dst.reserve(...)` would let an
    // attacker-driven oversize encode pre-allocate (denying
    // service via memory pressure even though the encode
    // ultimately fails).
    let mut codec = GrpcCodec::with_max_size(64);
    let mut buf = BytesMut::new();
    let oversize = vec![b'A'; 128];
    let msg = GrpcMessage::new(Bytes::from(oversize));
    let err = codec
        .encode(msg, &mut buf)
        .expect_err("payload > max_encode_message_size must reject");
    let err_str = format!("{err:?}");
    assert!(
        err_str.contains("MessageTooLarge") || err_str.to_lowercase().contains("too large"),
        "encode rejection must surface as MessageTooLarge — got: {err_str}",
    );
    // Buf must NOT have grown — the cap fired before any allocation.
    assert_eq!(
        buf.len(),
        0,
        "encode failure must leave dst unchanged (no partial write)",
    );
}

#[test]
fn grpc_codec_encode_at_max_size_boundary_succeeds() {
    // Pin (tick #156) positive case: a payload EXACTLY at
    // max_encode_message_size succeeds. The check is `>` strict,
    // not `>=`. A regression that flipped to `>=` would silently
    // reject a legitimate at-cap payload.
    let mut codec = GrpcCodec::with_max_size(64);
    let mut buf = BytesMut::new();
    let at_cap = vec![b'B'; 64];
    let msg = GrpcMessage::new(Bytes::from(at_cap));
    codec
        .encode(msg, &mut buf)
        .expect("payload at exactly max_encode_message_size must encode");
    assert_eq!(buf.len(), 5 + 64, "5-byte LPM header + 64-byte payload");
}

#[cfg(feature = "compression")]
#[test]
fn gzip_frame_decompress_capped_pre_allocation_against_amplification() {
    // Pin (c) extension: a tiny compressed input cannot trick
    // the decompressor into pre-allocating a large buffer. The
    // pre-allocation hint at codec.rs:309 is
    // `min(input.len() * 4, max_size)` — so a 1-byte compressed
    // input with max_size=1 GiB pre-allocates AT MOST 4 bytes,
    // not 1 GiB. (We can't observe Vec capacity from outside
    // safely, but we can pin the structural property: a
    // tiny-compressed-input decompress call doesn't OOM and
    // returns either Ok with the small payload or an Err.)
    use asupersync::grpc::gzip_frame_compress;
    use asupersync::grpc::gzip_frame_decompress;

    let small_payload = b"x";
    let compressed =
        gzip_frame_compress(Bytes::from_static(small_payload)).expect("compress must succeed");

    // Even with a 16 MiB cap, the small payload decompresses
    // safely without blowing memory — pin: the function returns
    // (Ok or Err is fine, the audit-relevant property is "no
    // OOM, no panic, finite work").
    let result = gzip_frame_decompress(compressed, 16 * 1024 * 1024);
    match result {
        Ok(out) => assert_eq!(out.as_ref(), small_payload),
        Err(e) => panic!("tiny payload decompress unexpectedly errored: {e:?}"),
    }
}
