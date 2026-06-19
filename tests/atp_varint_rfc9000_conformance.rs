//! RFC 9000 §16 QUIC variable-length integer conformance.
//!
//! Supports the adaptive-RaptorQ-over-QUIC epic (`asupersync-arq-quic-epic-b0k8qo`):
//! the `VarInt` codec in `src/net/atp/protocol/varint.rs` is the primitive every
//! QUIC frame, the DATAGRAM length field, and the transport parameters are built
//! from. The existing QUIC conformance suite only uses `VarInt` incidentally to
//! build ACK frames; this pins the codec itself — the four size classes, the
//! canonical wire bytes for the RFC's worked examples, the size-class boundaries,
//! `VARINT_MAX` (2^62 − 1) enforcement, and this implementation's deliberate
//! strictness: it **rejects non-canonical (non-minimal) encodings** rather than
//! silently accepting them, which a future "optimization" must not regress.
//!
//! Run with: `cargo test -p asupersync --test atp_varint_rfc9000_conformance`.

use asupersync::bytes::BytesMut;
use asupersync::net::atp::protocol::varint::{VARINT_MAX, VarInt};
use asupersync::types::outcome::Outcome;

fn encode(value: u64) -> Vec<u8> {
    let mut buf = BytesMut::new();
    VarInt::new(value).unwrap().encode(&mut buf).unwrap();
    buf.as_ref().to_vec()
}

/// Decodes one varint, returning `(value, bytes_consumed)`.
fn decode_ok(bytes: &[u8]) -> (u64, usize) {
    let mut buf = BytesMut::from(bytes);
    let before = buf.as_ref().len();
    match VarInt::decode(&mut buf) {
        Outcome::Ok(Some(v)) => (v.value(), before - buf.as_ref().len()),
        _ => panic!("expected a decoded varint from {bytes:?}"),
    }
}

/// The four worked decode examples from RFC 9000 §16.
#[test]
fn rfc9000_section16_decode_examples() {
    assert_eq!(
        decode_ok(&[0xc2, 0x19, 0x7c, 0x5e, 0xff, 0x14, 0xe8, 0x8c]),
        (151_288_809_941_952_652, 8),
    );
    assert_eq!(decode_ok(&[0x9d, 0x7f, 0x3e, 0x7d]), (494_878_333, 4));
    assert_eq!(decode_ok(&[0x7b, 0xbd]), (15_293, 2));
    assert_eq!(decode_ok(&[0x25]), (37, 1));
}

/// The canonical encoder reproduces the RFC's example byte sequences.
#[test]
fn canonical_encode_matches_rfc_examples() {
    assert_eq!(
        encode(151_288_809_941_952_652),
        vec![0xc2, 0x19, 0x7c, 0x5e, 0xff, 0x14, 0xe8, 0x8c],
    );
    assert_eq!(encode(494_878_333), vec![0x9d, 0x7f, 0x3e, 0x7d]);
    assert_eq!(encode(15_293), vec![0x7b, 0xbd]);
    assert_eq!(encode(37), vec![0x25]);
}

/// `encoded_len()` follows the §16 size classes exactly at every boundary.
#[test]
fn encoded_len_size_class_boundaries() {
    let cases = [
        (0u64, 1usize),
        (63, 1),
        (64, 2),
        (16_383, 2),
        (16_384, 4),
        (1_073_741_823, 4),
        (1_073_741_824, 8),
        (VARINT_MAX, 8),
    ];
    for (value, len) in cases {
        assert_eq!(
            VarInt::new(value).unwrap().encoded_len(),
            len,
            "value={value}"
        );
        assert_eq!(encode(value).len(), len, "encoded value={value}");
    }
}

/// `decode(encode(v)) == v` across every size class, consuming exactly the
/// canonical number of bytes.
#[test]
fn round_trip_across_size_classes() {
    let values = [
        0u64,
        1,
        63,
        64,
        16_383,
        16_384,
        1_073_741_823,
        1_073_741_824,
        VARINT_MAX,
        37,
        15_293,
        494_878_333,
        151_288_809_941_952_652,
    ];
    for value in values {
        let bytes = encode(value);
        assert_eq!(bytes.len(), VarInt::new(value).unwrap().encoded_len());
        assert_eq!(
            decode_ok(&bytes),
            (value, bytes.len()),
            "round-trip value={value}"
        );
    }
}

/// Values above `VARINT_MAX` (2^62 − 1) cannot be constructed.
#[test]
fn rejects_values_above_varint_max() {
    assert!(matches!(VarInt::new(VARINT_MAX), Outcome::Ok(_)));
    assert!(matches!(VarInt::new(VARINT_MAX + 1), Outcome::Err(_)));
    assert!(matches!(VarInt::new(u64::MAX), Outcome::Err(_)));
}

/// Non-canonical (non-minimal) encodings of a value are rejected — this codec is
/// strictly canonical on decode, not merely on encode.
#[test]
fn rejects_non_canonical_encodings() {
    // 37 padded into a 2-byte field (0x40 | 0x25) and a 4-byte field.
    let mut two = BytesMut::from([0x40u8, 0x25].as_slice());
    assert!(matches!(VarInt::decode(&mut two), Outcome::Err(_)));
    let mut four = BytesMut::from([0x80u8, 0x00, 0x00, 0x25].as_slice());
    assert!(matches!(VarInt::decode(&mut four), Outcome::Err(_)));
}

/// A buffer too short for the size class declared by the first byte yields
/// `Ok(None)` ("need more data") and consumes nothing.
#[test]
fn partial_buffer_needs_more_data() {
    let mut empty = BytesMut::new();
    assert!(matches!(VarInt::decode(&mut empty), Outcome::Ok(None)));

    // First byte 0x80 declares a 4-byte varint, but only two bytes are present.
    let mut partial = BytesMut::from([0x80u8, 0x00].as_slice());
    assert!(matches!(VarInt::decode(&mut partial), Outcome::Ok(None)));
    assert_eq!(
        partial.as_ref().len(),
        2,
        "Ok(None) must not consume the buffer"
    );
}

/// `peek_len` reports the size class from the first byte without consuming it.
#[test]
fn peek_len_reports_size_class_without_consuming() {
    let eight = BytesMut::from([0xc2u8, 0x19, 0x7c, 0x5e, 0xff, 0x14, 0xe8, 0x8c].as_slice());
    assert_eq!(VarInt::peek_len(&eight), Some(8));
    assert_eq!(eight.as_ref().len(), 8, "peek must not consume");

    assert_eq!(
        VarInt::peek_len(&BytesMut::from([0x25u8].as_slice())),
        Some(1)
    );
    assert_eq!(
        VarInt::peek_len(&BytesMut::from([0x40u8, 0x00].as_slice())),
        Some(2)
    );
    assert_eq!(VarInt::peek_len(&BytesMut::new()), None);
}
