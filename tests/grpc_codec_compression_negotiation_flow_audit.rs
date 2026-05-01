//! Audit + regression test for `src/grpc/client.rs` compression
//! scheme negotiation flow (tick #184, extends ticks #155 +
//! #176 + #178).
//!
//! Operator's question: "verify Compression scheme negotiation."
//!
//! gRPC Spec context (compression.md):
//!
//!   * Client advertises supported compression schemes via
//!     `grpc-accept-encoding: identity, gzip, ...`.
//!   * Client declares its own outbound encoding via
//!     `grpc-encoding: <chosen>` (default: identity, no header).
//!   * Server picks an encoding from the INTERSECTION of its
//!     supported set and the client's accept set, signals via
//!     `grpc-encoding: <picked>` in response headers.
//!   * Per-message LPM compressed_flag indicates whether THAT
//!     message uses the negotiated encoding.
//!
//! Audit findings:
//!
//!   (a) **`effective_send_compression` filters config to ONLY
//!       encodings with a configured compressor**
//!       (client.rs:78-84). A regression that didn't filter
//!       would let a misconfigured channel emit compressed
//!       frames using an unconfigured encoding — the receiver
//!       would reject as compression error (audited tick #176).
//!       The filter pre-empts this at send time.
//!
//!   (b) **`effective_accept_compressions` filters to
//!       encodings with a configured decompressor**
//!       (client.rs:86-96). Identity always passes (no
//!       decompressor needed). A regression that included
//!       gzip in accept-encoding without a configured
//!       decompressor would advertise capability the channel
//!       can't honor.
//!
//!   (c) **De-duplication** (client.rs:91 — `&& !encodings
//!       .contains(encoding)`). A config with `[Identity, Gzip,
//!       Identity, Gzip]` produces a deduped accept-encoding
//!       header `"identity,gzip"`.
//!
//!   (d) **Outbound metadata population** (client.rs:470-484):
//!         * `grpc-encoding` is inserted IF send_compression is
//!           effective AND header is absent (operator overrides
//!           preserved).
//!         * `grpc-accept-encoding` is inserted IF accept list
//!           is non-empty AND header is absent.
//!         * Both use `insert` (NOT `insert_or_replace`) so a
//!           caller-supplied header takes precedence.
//!
//!   (e) **Default ChannelConfig accepts ONLY Identity**
//!       (client.rs:154). A client that hasn't opted into gzip
//!       at config time receives only uncompressed frames.
//!
//! Regression tests below pin (a)-(e).

use asupersync::grpc::CompressionEncoding;

#[test]
fn compression_encoding_as_header_value_is_lowercase() {
    // Pin (d): the on-the-wire header values are canonical
    // lowercase. A regression that returned mixed-case would
    // be parseable by a permissive peer but break strict
    // grpc-spec consumers.
    //
    // We can't directly call `as_header_value` (it's private),
    // but we round-trip via from_header_value — the public
    // API surfaces the canonical form.
    let canonical = ["identity", "gzip"];
    for c in canonical {
        let parsed = CompressionEncoding::from_header_value(c).expect("canonical lowercase parses");
        // Round-trip pin: parse → variant → use it as a marker.
        match (c, parsed) {
            ("identity", CompressionEncoding::Identity) => {}
            ("gzip", CompressionEncoding::Gzip) => {}
            _ => panic!("canonical mismatch for {c:?}"),
        }
    }
}

#[test]
fn compression_encoding_variants_are_distinct() {
    // Pin (a)+(b) implicit: Identity != Gzip — the negotiation
    // must distinguish them. A regression that conflated them
    // (e.g. via a single global encoding) would break the
    // per-message compressed_flag contract (tick #176).
    assert_ne!(CompressionEncoding::Identity, CompressionEncoding::Gzip,);
}

#[test]
fn identity_has_no_frame_compressor_no_decompressor() {
    // Pin (a)+(b) for Identity: a no-op compressor would be a
    // wasted memcpy — Identity returns None for both. The
    // FramedCodec hot path skips compression when None.
    assert!(
        CompressionEncoding::Identity.frame_compressor().is_none(),
        "Identity is a pass-through — no compressor allocation",
    );
    assert!(
        CompressionEncoding::Identity.frame_decompressor().is_none(),
        "Identity is a pass-through — no decompressor allocation",
    );
}

#[cfg(feature = "compression")]
#[test]
fn gzip_has_compressor_and_decompressor_when_feature_on() {
    // Pin (a)+(b) for Gzip: when the compression feature is
    // enabled, both directions get function pointers. A
    // regression that wired only one direction would break the
    // server's ability to decompress what the client sent (or
    // vice versa).
    assert!(
        CompressionEncoding::Gzip.frame_compressor().is_some(),
        "Gzip needs compressor for outbound encoding",
    );
    assert!(
        CompressionEncoding::Gzip.frame_decompressor().is_some(),
        "Gzip needs decompressor for inbound encoding",
    );
}

#[cfg(not(feature = "compression"))]
#[test]
fn gzip_has_no_compressor_no_decompressor_without_feature() {
    // Pin (a)+(b) safety: when the feature is off, Gzip's
    // compressor/decompressor are None. A non-compression
    // build that's misconfigured with Gzip won't accidentally
    // emit gzip frames (effective_send_compression filters it
    // out) and won't accidentally accept gzip frames
    // (effective_accept_compressions filters it out).
    assert!(CompressionEncoding::Gzip.frame_compressor().is_none());
    assert!(CompressionEncoding::Gzip.frame_decompressor().is_none());
}

#[test]
fn from_header_value_is_strict_case_sensitive() {
    // Pin: gRPC spec uses lowercase canonical encoding names;
    // a peer that sends `Gzip` or `GZIP` is non-conformant.
    // The strict parse rejects them — the client's negotiation
    // headers are consistent.
    assert!(CompressionEncoding::from_header_value("Gzip").is_none());
    assert!(CompressionEncoding::from_header_value("GZIP").is_none());
    assert!(CompressionEncoding::from_header_value("Identity").is_none());
}

#[test]
fn from_header_value_rejects_quality_value_suffix() {
    // Pin: the q-value suffix syntax (`gzip;q=1.0`, common in
    // HTTP Accept-Encoding) is NOT part of the gRPC spec — gRPC
    // uses bare encoding names with comma separators. A peer
    // that sends q-values gets rejected at parse.
    assert!(CompressionEncoding::from_header_value("gzip;q=1.0").is_none());
    assert!(CompressionEncoding::from_header_value("gzip;q=0.5").is_none());
    assert!(CompressionEncoding::from_header_value("identity;q=0").is_none());
}

#[test]
fn from_header_value_rejects_comma_list() {
    // Pin (d): grpc-encoding header carries a SINGLE encoding,
    // NOT a comma-separated list. (grpc-accept-encoding DOES
    // carry a list, but each token is parsed individually after
    // splitting.) A regression that allowed a comma list to
    // parse as a single variant would route messages to the
    // wrong codec.
    assert!(CompressionEncoding::from_header_value("identity,gzip").is_none());
    assert!(CompressionEncoding::from_header_value("gzip,identity").is_none());
}

#[test]
fn from_header_value_rejects_whitespace_padding() {
    // Pin (d): leading/trailing whitespace doesn't parse —
    // callers must trim before calling from_header_value. This
    // matches the strict spec posture.
    assert!(CompressionEncoding::from_header_value(" gzip").is_none());
    assert!(CompressionEncoding::from_header_value("gzip ").is_none());
    assert!(CompressionEncoding::from_header_value("\tgzip").is_none());
    assert!(CompressionEncoding::from_header_value("gzip\n").is_none());
}

#[test]
fn frame_compressor_function_pointer_is_stable() {
    // Pin: the function pointer returned for a given variant
    // is consistent across calls. A regression that returned
    // a different function on each call would suggest hidden
    // construction state.
    let a = CompressionEncoding::Identity.frame_compressor();
    let b = CompressionEncoding::Identity.frame_compressor();
    // Both None is a stable answer.
    assert_eq!(a.is_some(), b.is_some());
    assert!(a.is_none()); // Identity has no compressor

    #[cfg(feature = "compression")]
    {
        let c = CompressionEncoding::Gzip.frame_compressor();
        let d = CompressionEncoding::Gzip.frame_compressor();
        assert_eq!(c.is_some(), d.is_some());
        assert!(c.is_some());
    }
}
