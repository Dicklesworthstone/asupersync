//! Property/fuzz hardening for the RaptorQ-over-QUIC symbol-envelope codec
//! (b0k8qo.2.2 foundation / H6 symbol-envelope schema).
//!
//! `QuicSymbolEnvelope::decode` parses untrusted bytes off a QUIC DATAGRAM, so
//! totality matters: it must never panic on arbitrary, truncated, or corrupted
//! input — only ever returning `Ok` or a typed error. This suite fuzzes:
//!
//! - **decode is total** on arbitrary bytes + either auth posture (no panic);
//! - **encode/decode round-trip** preserves every field of a valid envelope;
//! - **auth-posture mismatch always fails closed** (never a silent wrong parse);
//! - **truncation and single-byte corruption never panic**.
//!
//! Pure codec (no runtime/features needed).

#![allow(missing_docs)]

use asupersync::bytes::Bytes;
use asupersync::net::atp::transport_quic::QuicSymbolEnvelope;
use proptest::prelude::*;

/// A strategy producing arbitrary valid envelopes (payload bounded for speed;
/// well under the `u16` length-field limit so `encode` always succeeds).
fn env_strat() -> impl Strategy<Value = QuicSymbolEnvelope> {
    (
        any::<u64>(),
        any::<u32>(),
        any::<u8>(),
        any::<u32>(),
        any::<bool>(),
        any::<bool>(),
        prop::array::uniform32(any::<u8>()),
        prop::collection::vec(any::<u8>(), 0..600),
    )
        .prop_map(
            |(transfer_tag, entry, sbn, esi, is_repair, has_auth, tag, payload)| {
                QuicSymbolEnvelope {
                    transfer_tag,
                    entry,
                    sbn,
                    esi,
                    is_repair,
                    auth_tag: if has_auth { Some(tag) } else { None },
                    payload: Bytes::from(payload),
                }
            },
        )
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    /// decode never panics on arbitrary bytes under either auth posture.
    #[test]
    fn decode_is_total_on_arbitrary_bytes(
        bytes in prop::collection::vec(any::<u8>(), 0..1024),
        auth in any::<bool>(),
    ) {
        // The only requirement: this returns (Ok | Err) without panicking.
        let _ = QuicSymbolEnvelope::decode(&bytes, auth);
        prop_assert!(true);
    }

    /// encode then decode (matching posture) recovers the exact envelope.
    #[test]
    fn encode_decode_roundtrip(env in env_strat()) {
        let auth = env.auth_tag.is_some();
        let bytes = env.encode().expect("bounded payload encodes");
        let back = QuicSymbolEnvelope::decode(&bytes, auth).expect("valid envelope decodes");
        prop_assert_eq!(env, back);
    }

    /// Decoding a validly-encoded envelope under the WRONG auth posture always
    /// fails closed (never a silent mis-parse) and never panics.
    #[test]
    fn auth_posture_mismatch_fails_closed(env in env_strat()) {
        let bytes = env.encode().unwrap();
        let wrong = env.auth_tag.is_none(); // opposite of how it was encoded
        prop_assert!(QuicSymbolEnvelope::decode(&bytes, wrong).is_err());
    }

    /// Truncating a valid envelope at any offset never panics.
    #[test]
    fn truncation_never_panics(env in env_strat(), cut in any::<prop::sample::Index>()) {
        let bytes = env.encode().unwrap();
        let auth = env.auth_tag.is_some();
        let n = cut.index(bytes.len() + 1); // 0..=len
        let _ = QuicSymbolEnvelope::decode(&bytes[..n], auth);
        prop_assert!(true);
    }

    /// Flipping one byte of a valid envelope never panics (decode stays total).
    #[test]
    fn single_byte_corruption_never_panics(
        env in env_strat(),
        idx in any::<prop::sample::Index>(),
        xor in 1u8..=255,
    ) {
        let mut bytes = env.encode().unwrap().to_vec();
        if !bytes.is_empty() {
            let i = idx.index(bytes.len());
            bytes[i] ^= xor;
            let auth = env.auth_tag.is_some();
            let _ = QuicSymbolEnvelope::decode(&bytes, auth);
        }
        prop_assert!(true);
    }
}
