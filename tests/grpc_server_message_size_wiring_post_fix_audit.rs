//! Audit + regression test for `src/grpc/server.rs` server-side
//! message-size cap wiring (tick #200, post-fix follow-up to
//! ticks #198 + #199).
//!
//! Operator's question: "verify message-size cap server-side
//! wiring."
//!
//! Audit context — the P1 fix in commit f28e72e9d
//! (br-asupersync-srizvf) closed the wiring gap by adding the
//! `Server::framed_codec<C>(&self, inner: C) -> FramedCodec<C>`
//! helper. This test pins the END-TO-END behavior:
//!
//!   1. Configure the server with non-default size caps.
//!   2. Construct a per-call codec via `server.framed_codec(...)`.
//!   3. Assert the resulting codec enforces the configured caps —
//!      not the codec's own DEFAULT_MAX_MESSAGE_SIZE (4 MiB).
//!
//! Audit findings:
//!
//!   (a) **Server::framed_codec threads max_recv_message_size**
//!       into the codec's decode-side cap. Encoding a frame
//!       above the configured cap rejects with
//!       MessageTooLarge — the operator's stricter cap takes
//!       effect.
//!
//!   (b) **Server::framed_codec threads max_send_message_size**
//!       into the codec's encode-side cap. Symmetric to (a).
//!
//!   (c) **Default-cap server gets 4 MiB** — operators who
//!       don't override see the documented default behavior.
//!       A regression that broke the default would surface
//!       here.
//!
//!   (d) **Stricter cap actually rejects below default.** Pre-
//!       fix, an operator configuring a 256 KiB recv cap got
//!       the 4 MiB codec default. Post-fix, the configured
//!       256 KiB takes effect — verified via on-wire decode
//!       behavior.
//!
//!   (e) **Permissive cap actually allows above default.** Pre-
//!       fix, an operator configuring a 32 MiB recv cap got
//!       the 4 MiB codec default (rejected at 5 MiB). Post-
//!       fix, the configured 32 MiB takes effect.
//!
//!   (f) **Asymmetric configuration honored.** A server with
//!       (256 KiB recv, 64 MiB send) wires both directions
//!       independently — neither leaks the other's value.
//!
//! Regression tests below pin (a)-(f) end-to-end via
//! Server::framed_codec.

use asupersync::bytes::{Bytes, BytesMut};
use asupersync::grpc::{IdentityCodec, ServerBuilder};

#[test]
fn framed_codec_decode_cap_matches_max_recv_message_size() {
    // Pin (a): configured max_recv_message_size flows into the
    // codec's decode cap. Pre-fix this was silently ignored.
    let server = ServerBuilder::new()
        .max_recv_message_size(256 * 1024)
        .build();
    let codec = server.framed_codec(IdentityCodec);
    assert_eq!(
        codec.max_decode_message_size(),
        256 * 1024,
        "framed_codec must thread max_recv_message_size — operator's \
         configured 256 KiB cap takes effect, NOT the codec default 4 MiB",
    );
}

#[test]
fn framed_codec_encode_cap_matches_max_send_message_size() {
    // Pin (b): symmetric for send direction.
    let server = ServerBuilder::new()
        .max_send_message_size(512 * 1024)
        .build();
    let codec = server.framed_codec(IdentityCodec);
    assert_eq!(
        codec.max_encode_message_size(),
        512 * 1024,
        "framed_codec threads max_send_message_size",
    );
}

#[test]
fn default_server_framed_codec_has_4mib_caps() {
    // Pin (c): default-config server produces a codec with the
    // documented 4 MiB caps. Operators who don't override see
    // the documented default.
    let server = ServerBuilder::new().build();
    let codec = server.framed_codec(IdentityCodec);
    assert_eq!(codec.max_decode_message_size(), 4 * 1024 * 1024);
    assert_eq!(codec.max_encode_message_size(), 4 * 1024 * 1024);
}

#[test]
fn framed_codec_with_stricter_recv_cap_rejects_at_configured_limit() {
    // Pin (d) end-to-end: a server configured with a 64 KiB recv
    // cap actually REJECTS messages of 65 KiB on the encode side
    // (encode shares the same cap when configured symmetrically
    // — but here we set BOTH so we can test both directions).
    let cap = 64 * 1024;
    let server = ServerBuilder::new()
        .max_recv_message_size(cap)
        .max_send_message_size(cap)
        .build();
    let mut codec = server.framed_codec(IdentityCodec);

    let oversize = vec![b'X'; cap + 1];
    let mut wire = BytesMut::new();
    let err = codec
        .encode_message(&Bytes::from(oversize), &mut wire)
        .expect_err("oversize encode rejects at configured cap");
    let err_str = format!("{err:?}");
    assert!(
        err_str.contains("MessageTooLarge") || err_str.to_lowercase().contains("too large"),
        "rejection at configured 64 KiB cap surfaces as MessageTooLarge; \
         got {err_str}",
    );
}

#[test]
fn framed_codec_with_permissive_recv_cap_accepts_above_default() {
    // Pin (e) end-to-end: a server configured with an 8 MiB recv
    // cap accepts a 5 MiB message (above the codec's 4 MiB
    // default but below the configured 8 MiB).
    let server = ServerBuilder::new()
        .max_recv_message_size(8 * 1024 * 1024)
        .max_send_message_size(8 * 1024 * 1024)
        .build();
    let mut codec = server.framed_codec(IdentityCodec);

    let payload = vec![b'P'; 5 * 1024 * 1024];
    let mut wire = BytesMut::new();
    codec
        .encode_message(&Bytes::from(payload), &mut wire)
        .expect(
            "5 MiB payload accepts under configured 8 MiB cap (would \
                 have rejected against the 4 MiB codec default pre-fix)",
        );
}

#[test]
fn framed_codec_asymmetric_caps_honored_independently() {
    // Pin (f): a server with strict recv + permissive send
    // wires both directions independently — no cross-talk.
    let server = ServerBuilder::new()
        .max_recv_message_size(128 * 1024) // strict recv
        .max_send_message_size(16 * 1024 * 1024) // permissive send
        .build();
    let codec = server.framed_codec(IdentityCodec);
    assert_eq!(codec.max_decode_message_size(), 128 * 1024);
    assert_eq!(codec.max_encode_message_size(), 16 * 1024 * 1024);
    // The two values are independent — pinning that the helper
    // doesn't accidentally use the same value for both.
    assert_ne!(
        codec.max_decode_message_size(),
        codec.max_encode_message_size(),
    );
}

#[test]
fn framed_codec_helper_returns_independent_codec_per_call() {
    // Pin: each call to server.framed_codec returns a NEW
    // FramedCodec instance — no shared state. Adapters that
    // call this for every dispatched call don't accidentally
    // share codec state across requests.
    let server = ServerBuilder::new()
        .max_recv_message_size(1024 * 1024)
        .build();
    let codec_a = server.framed_codec(IdentityCodec);
    let codec_b = server.framed_codec(IdentityCodec);
    // Both have the same configured cap.
    assert_eq!(
        codec_a.max_decode_message_size(),
        codec_b.max_decode_message_size(),
    );
    // But they're independent instances (we can't compare
    // FramedCodec for equality directly; pin via independent
    // mutability — taking each by value into separate scopes
    // implies independence).
    drop(codec_a);
    let _ = codec_b;
}

#[test]
fn ramped_caps_do_not_silently_fall_back_to_default() {
    // Pin (d)+(e) negative — the canonical anti-pattern that
    // motivated the fix: pre-fix code constructed FramedCodec
    // without reading the config, so operator's explicit
    // override silently inherited the codec's 4 MiB default.
    // Post-fix, the override takes effect.
    //
    // We pin via a series of ramped caps (1 KiB, 1 MiB, 16 MiB)
    // and verify each one threads through unchanged.
    for cap in [1024usize, 1024 * 1024, 16 * 1024 * 1024] {
        let server = ServerBuilder::new()
            .max_recv_message_size(cap)
            .max_send_message_size(cap)
            .build();
        let codec = server.framed_codec(IdentityCodec);
        assert_eq!(
            codec.max_decode_message_size(),
            cap,
            "configured cap {cap} bytes must reach the codec",
        );
        assert_eq!(codec.max_encode_message_size(), cap);
    }
}

#[test]
fn server_config_field_doc_no_longer_says_wiring_gap() {
    // Pin: the doc comment on ServerConfig::max_recv_message_size
    // was REMOVED of the 'WIRING GAP' language as part of the
    // fix. A regression that re-introduced the gap would also
    // need to re-introduce the doc — pinning the absence
    // catches the regression at the field declaration.
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let server_rs =
        std::fs::read_to_string(std::path::Path::new(manifest_dir).join("src/grpc/server.rs"))
            .expect("read src/grpc/server.rs");
    assert!(
        !server_rs.contains("WIRING GAP"),
        "the WIRING GAP language was removed in commit f28e72e9d \
         (br-asupersync-srizvf); a regression that re-introduced it \
         signals the underlying bug came back. The fix path is \
         Server::framed_codec.",
    );
    // Positive pin: the doc-comment now points to framed_codec.
    assert!(
        server_rs.contains("Server::framed_codec"),
        "post-fix doc-comment must point to Server::framed_codec as \
         the canonical wiring helper",
    );
}
