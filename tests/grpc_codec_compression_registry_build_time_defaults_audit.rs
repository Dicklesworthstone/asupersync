//! Audit + regression test for `src/grpc/codec.rs` compression
//! registry build-time defaults (tick #202).
//!
//! Operator's question: "verify Compression registry build-time
//! defaults."
//!
//! Audit context — when an operator builds a `FramedCodec` with
//! the simplest constructor (`FramedCodec::new(IdentityCodec)`),
//! what compression posture is wired? The audit-relevant pin: a
//! freshly-constructed codec is identity-only — compression
//! must be EXPLICITLY OPTED IN via builder methods. A
//! regression that defaulted compression-on at construction
//! time would change the wire bytes for every codec instance
//! and break vanilla gRPC clients that don't advertise gzip.
//!
//! Audit findings:
//!
//!   (a) **`FramedCodec::new` defaults to no compression**
//!       (codec.rs:362-364, calls with_message_size_limits
//!       which initializes use_compression: false, compressor:
//!       None, decompressor: None at codec.rs:387-389). Wire-
//!       level identity-only by default.
//!
//!   (b) **Default size cap is 4 MiB** (codec.rs:363, via
//!       DEFAULT_MAX_MESSAGE_SIZE on both encode and decode).
//!       Symmetric defaults — operator override flows through
//!       with_message_size_limits / with_max_size.
//!
//!   (c) **`with_compression()` flips use_compression flag
//!       WITHOUT installing hooks** (codec.rs:411-414). This is
//!       a separate from with_frame_hooks — it just toggles
//!       the FLAG. A regression that enabled compression
//!       without setting hooks would lead to the codec
//!       attempting to compress with a None hook and
//!       silently no-op'ing OR rejecting at runtime.
//!
//!   (d) **`with_frame_hooks(Some, Some)` sets BOTH
//!       compressor + decompressor AND flips
//!       use_compression** (codec.rs:401-403, 404-405). The
//!       canonical wiring path — compression hooks come as a
//!       PAIR.
//!
//!   (e) **`with_gzip_frame_codec` is feature-flag gated
//!       behind `compression`** (codec.rs:432). A non-
//!       compression build cannot accidentally enable gzip
//!       at construction time.
//!
//!   (f) **`with_identity_frame_codec` wires identity hooks
//!       symmetrically while keeping use_compression false**
//!       (codec.rs:443-450). Identity is the no-op pair —
//!       operators who want to make the passthrough EXPLICIT
//!       in the codec configuration use this method without
//!       changing outbound compressed-flag bytes.
//!
//!   (g) **`poisoned: false` initial state** (codec.rs:390).
//!       A fresh codec is NOT poisoned — first frame can
//!       decode normally. Poison fires on the first protocol
//!       error (audited tick #176).
//!
//! Regression tests below pin (a)+(b)+(c)+(d)+(f)+(g) at the
//! public API surface.

use asupersync::grpc::{FramedCodec, IdentityCodec};

#[test]
fn fresh_framed_codec_has_no_compressor_no_decompressor() {
    // Pin (a): the canonical "no compression configured"
    // build-time default. A regression that defaulted to
    // gzip-on would change wire bytes for every codec.
    let codec: FramedCodec<IdentityCodec> = FramedCodec::new(IdentityCodec);
    let dbg = format!("{codec:?}");
    // Debug impl exposes has_compressor + has_decompressor
    // booleans (codec.rs:352-353).
    assert!(
        dbg.contains("has_compressor: false"),
        "fresh FramedCodec must have NO compressor configured; got {dbg}",
    );
    assert!(
        dbg.contains("has_decompressor: false"),
        "fresh FramedCodec must have NO decompressor configured; got {dbg}",
    );
}

#[test]
fn fresh_framed_codec_has_use_compression_false() {
    // Pin (a): the use_compression flag is false at
    // construction. A regression to true would surface here.
    let codec: FramedCodec<IdentityCodec> = FramedCodec::new(IdentityCodec);
    let dbg = format!("{codec:?}");
    assert!(
        dbg.contains("use_compression: false"),
        "fresh codec's use_compression flag must be false; got {dbg}",
    );
}

#[test]
fn fresh_framed_codec_has_4mib_size_cap() {
    // Pin (b): default size cap is 4 MiB on both directions.
    let codec: FramedCodec<IdentityCodec> = FramedCodec::new(IdentityCodec);
    assert_eq!(
        codec.max_decode_message_size(),
        4 * 1024 * 1024,
        "fresh codec default decode cap is 4 MiB",
    );
    assert_eq!(
        codec.max_encode_message_size(),
        4 * 1024 * 1024,
        "fresh codec default encode cap is 4 MiB",
    );
}

#[test]
fn fresh_framed_codec_is_not_poisoned() {
    // Pin (g): initial poisoned state is false. A regression
    // that defaulted to poisoned=true would reject every
    // first-frame decode immediately.
    let codec: FramedCodec<IdentityCodec> = FramedCodec::new(IdentityCodec);
    let dbg = format!("{codec:?}");
    assert!(
        dbg.contains("poisoned: false"),
        "fresh codec must NOT be poisoned; got {dbg}",
    );
}

#[test]
fn with_compression_sets_flag_without_hooks() {
    // Pin (c): with_compression() toggles use_compression but
    // does NOT install any hooks. Operators using this path
    // must follow up with with_frame_hooks/with_frame_codec/
    // with_gzip_frame_codec/with_identity_frame_codec.
    let codec = FramedCodec::new(IdentityCodec).with_compression();
    let dbg = format!("{codec:?}");
    assert!(dbg.contains("use_compression: true"));
    assert!(
        dbg.contains("has_compressor: false"),
        "with_compression alone does NOT install a compressor; got {dbg}",
    );
    assert!(dbg.contains("has_decompressor: false"));
}

#[test]
fn with_frame_hooks_some_some_installs_pair_and_sets_flag() {
    // Pin (d): with_frame_hooks(Some, Some) is the canonical
    // wiring path — compressor and decompressor come as a
    // pair, and use_compression flips to true.
    fn dummy_compressor(
        input: asupersync::bytes::Bytes,
    ) -> Result<asupersync::bytes::Bytes, asupersync::grpc::status::GrpcError> {
        Ok(input)
    }
    fn dummy_decompressor(
        input: asupersync::bytes::Bytes,
        _max_size: usize,
    ) -> Result<asupersync::bytes::Bytes, asupersync::grpc::status::GrpcError> {
        Ok(input)
    }
    let codec = FramedCodec::new(IdentityCodec)
        .with_frame_hooks(Some(dummy_compressor), Some(dummy_decompressor));
    let dbg = format!("{codec:?}");
    assert!(dbg.contains("use_compression: true"));
    assert!(dbg.contains("has_compressor: true"));
    assert!(dbg.contains("has_decompressor: true"));
}

#[test]
fn with_frame_hooks_none_none_does_not_set_flag() {
    // Pin (d) edge: with_frame_hooks(None, None) is a no-op
    // for the use_compression flag — it stays at the
    // construction default (false).
    let codec = FramedCodec::new(IdentityCodec).with_frame_hooks(None, None);
    let dbg = format!("{codec:?}");
    assert!(
        dbg.contains("use_compression: false"),
        "(None, None) hooks must NOT set use_compression",
    );
    assert!(dbg.contains("has_compressor: false"));
    assert!(dbg.contains("has_decompressor: false"));
}

#[test]
fn with_identity_frame_codec_wires_identity_pair() {
    // Pin (f): with_identity_frame_codec installs the explicit
    // identity (no-op) pair while preserving compressed-flag=0
    // for outbound frames — used when operators want identity to
    // be EXPLICIT in the codec config rather than implicit
    // absence-of-hooks.
    let codec = FramedCodec::new(IdentityCodec).with_identity_frame_codec();
    let dbg = format!("{codec:?}");
    assert!(dbg.contains("use_compression: false"));
    assert!(dbg.contains("has_compressor: true"));
    assert!(dbg.contains("has_decompressor: true"));
}

#[cfg(feature = "compression")]
#[test]
fn with_gzip_frame_codec_wires_gzip_pair_when_feature_on() {
    // Pin (e) positive: when the compression feature is
    // enabled, with_gzip_frame_codec installs gzip's
    // compressor + decompressor pair.
    let codec = FramedCodec::new(IdentityCodec).with_gzip_frame_codec();
    let dbg = format!("{codec:?}");
    assert!(dbg.contains("has_compressor: true"));
    assert!(dbg.contains("has_decompressor: true"));
}

#[test]
fn with_max_size_overrides_default_cap_symmetrically() {
    // Pin (b) extension: with_max_size sets BOTH directions
    // to the same value. A regression that only set one
    // direction would let attackers send oversized one-way
    // traffic.
    let codec = FramedCodec::with_max_size(IdentityCodec, 1024 * 1024);
    assert_eq!(codec.max_decode_message_size(), 1024 * 1024);
    assert_eq!(codec.max_encode_message_size(), 1024 * 1024);
}

#[test]
fn with_message_size_limits_overrides_each_direction_independently() {
    // Pin (b): independent decode/encode caps.
    let codec = FramedCodec::with_message_size_limits(
        IdentityCodec,
        512 * 1024,      // encode
        2 * 1024 * 1024, // decode
    );
    assert_eq!(codec.max_encode_message_size(), 512 * 1024);
    assert_eq!(codec.max_decode_message_size(), 2 * 1024 * 1024);
}

#[test]
fn fresh_codec_construction_is_lightweight() {
    // Pin: constructing a FramedCodec is allocation-light.
    // Build 1000 codecs in a row — no panic, no allocation
    // pressure.
    for _ in 0..1000 {
        let _codec: FramedCodec<IdentityCodec> = FramedCodec::new(IdentityCodec);
    }
}

#[test]
fn build_time_defaults_documented_via_debug_format() {
    // Pin (a)+(g): the Debug impl exposes the three audit-
    // relevant flags (has_compressor, has_decompressor,
    // poisoned) so operators can grep / log to verify the
    // codec posture at startup. A regression that hid these
    // flags from Debug would lose this diagnostic.
    let codec: FramedCodec<IdentityCodec> = FramedCodec::new(IdentityCodec);
    let dbg = format!("{codec:?}");
    assert!(dbg.contains("has_compressor"));
    assert!(dbg.contains("has_decompressor"));
    assert!(dbg.contains("poisoned"));
    assert!(dbg.contains("use_compression"));
}
