//! ATP-over-QUIC RaptorQ symbol-envelope wire conformance (b0k8qo.2.2 foundation
//! / H6 `.9.6` deferred symbol-envelope schema).
//!
//! Pins, from OUTSIDE the crate, the byte-level contract of the symbol envelope
//! carried inside a QUIC DATAGRAM: header layout (golden offsets), encode→decode
//! round-trip across boundaries, and fail-closed rejection of every malformed or
//! foreign input (wrong magic, truncation, length mismatch, bad repair flag,
//! auth-posture mismatch, oversize payload). Public API, no features required.

#![allow(missing_docs)]

use asupersync::bytes::Bytes;
use asupersync::net::atp::transport_quic::{
    ATP_QUIC_SYMBOL_MAGIC, AUTH_ENVELOPE_HEADER_LEN, ENVELOPE_HEADER_LEN, QuicSymbolEnvelope,
    QuicSymbolEnvelopeError,
};

const TAG_SIZE: usize = 32;

fn sample(auth: bool, payload: &'static [u8]) -> QuicSymbolEnvelope {
    QuicSymbolEnvelope {
        transfer_tag: 0xDEAD_BEEF_0BAD_F00D,
        entry: 42,
        sbn: 9,
        esi: 0x00AB_CDEF,
        is_repair: false,
        auth_tag: if auth { Some([0x5Au8; TAG_SIZE]) } else { None },
        payload: Bytes::from_static(payload),
    }
}

#[test]
fn header_constants_are_consistent() {
    assert_eq!(ENVELOPE_HEADER_LEN, 24);
    assert_eq!(AUTH_ENVELOPE_HEADER_LEN, ENVELOPE_HEADER_LEN + TAG_SIZE);
    assert_eq!(ATP_QUIC_SYMBOL_MAGIC, u32::from_be_bytes(*b"ATQS"));
}

#[test]
fn golden_header_layout() {
    let env = sample(false, b"symbol-payload");
    let b = env.encode().unwrap();
    assert_eq!(b.len(), ENVELOPE_HEADER_LEN + env.payload.len());
    assert_eq!(&b[0..4], b"ATQS");
    assert_eq!(&b[4..12], &0xDEAD_BEEF_0BAD_F00Du64.to_be_bytes());
    assert_eq!(&b[12..16], &42u32.to_be_bytes());
    assert_eq!(b[16], 9);
    assert_eq!(&b[17..21], &0x00AB_CDEFu32.to_be_bytes());
    assert_eq!(b[21], 0); // source symbol
    assert_eq!(&b[22..24], &(env.payload.len() as u16).to_be_bytes());
    assert_eq!(&b[24..], env.payload.as_ref());
}

#[test]
fn roundtrip_source_and_repair_with_and_without_auth() {
    for auth in [false, true] {
        for repair in [false, true] {
            let mut env = sample(auth, b"abcdefghijklmnopqrstuvwxyz");
            env.is_repair = repair;
            let bytes = env.encode().unwrap();
            let decoded = QuicSymbolEnvelope::decode(&bytes, auth).unwrap();
            assert_eq!(env, decoded, "auth={auth} repair={repair}");
        }
    }
}

#[test]
fn empty_and_max_u16_payload_roundtrip() {
    // Empty payload.
    let mut env = sample(false, b"");
    let b = env.encode().unwrap();
    assert_eq!(b.len(), ENVELOPE_HEADER_LEN);
    assert_eq!(QuicSymbolEnvelope::decode(&b, false).unwrap(), env);

    // Exactly u16::MAX payload (the largest the length field encodes).
    env.payload = Bytes::from(vec![0x7u8; usize::from(u16::MAX)]);
    let b = env.encode().unwrap();
    let back = QuicSymbolEnvelope::decode(&b, false).unwrap();
    assert_eq!(back.payload.len(), usize::from(u16::MAX));
    assert_eq!(env, back);
}

#[test]
fn payload_over_u16_fails_closed_on_encode() {
    let env = QuicSymbolEnvelope {
        payload: Bytes::from(vec![0u8; usize::from(u16::MAX) + 1]),
        ..sample(false, b"")
    };
    assert!(matches!(
        env.encode(),
        Err(QuicSymbolEnvelopeError::PayloadTooLarge { .. })
    ));
}

#[test]
fn decode_rejects_wrong_magic() {
    let mut b = sample(false, b"xyz").encode().unwrap().to_vec();
    b[1] ^= 0xFF;
    assert!(matches!(
        QuicSymbolEnvelope::decode(&b, false),
        Err(QuicSymbolEnvelopeError::BadMagic { .. })
    ));
}

#[test]
fn decode_rejects_truncation_and_length_mismatch() {
    let b = sample(false, b"payload-bytes").encode().unwrap();
    // Below the header.
    assert!(matches!(
        QuicSymbolEnvelope::decode(&b[..ENVELOPE_HEADER_LEN - 1], false),
        Err(QuicSymbolEnvelopeError::TooShort { .. })
    ));
    // Header intact but a payload byte dropped -> declared != available.
    assert!(matches!(
        QuicSymbolEnvelope::decode(&b[..b.len() - 1], false),
        Err(QuicSymbolEnvelopeError::LengthMismatch { .. })
    ));
    // Extra trailing byte -> also a mismatch (exact-length contract).
    let mut extra = b.to_vec();
    extra.push(0);
    assert!(matches!(
        QuicSymbolEnvelope::decode(&extra, false),
        Err(QuicSymbolEnvelopeError::LengthMismatch { .. })
    ));
}

#[test]
fn decode_rejects_invalid_repair_flag() {
    let mut b = sample(false, b"x").encode().unwrap().to_vec();
    b[21] = 0xFF;
    assert!(matches!(
        QuicSymbolEnvelope::decode(&b, false),
        Err(QuicSymbolEnvelopeError::InvalidRepairFlag { byte: 0xFF })
    ));
}

#[test]
fn auth_posture_mismatch_fails_closed_both_directions() {
    let with_auth = sample(true, b"payload").encode().unwrap();
    assert!(QuicSymbolEnvelope::decode(&with_auth, false).is_err());
    let without_auth = sample(false, b"payload").encode().unwrap();
    assert!(QuicSymbolEnvelope::decode(&without_auth, true).is_err());
}

#[test]
fn metamorphic_each_routing_field_changes_the_wire() {
    let base = sample(false, b"payload").encode().unwrap();
    let mutate = |f: &dyn Fn(&mut QuicSymbolEnvelope)| {
        let mut e = sample(false, b"payload");
        f(&mut e);
        e.encode().unwrap()
    };
    assert_ne!(base, mutate(&|e| e.transfer_tag ^= 1));
    assert_ne!(base, mutate(&|e| e.entry += 1));
    assert_ne!(base, mutate(&|e| e.sbn ^= 1));
    assert_ne!(base, mutate(&|e| e.esi += 1));
    assert_ne!(base, mutate(&|e| e.is_repair = true));
}
