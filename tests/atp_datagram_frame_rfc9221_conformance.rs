//! RFC 9221 QUIC DATAGRAM frame wire-format conformance.
//!
//! Supports the adaptive-RaptorQ-over-QUIC epic (`asupersync-arq-quic-epic-b0k8qo`,
//! Phase A datagram send/recv): the `DatagramFrame` codec in
//! `src/net/atp/datagram/frame.rs` is what A1/A2 serialize onto and parse off the
//! wire. The module's inline tests cover basic round-trips; this external suite
//! pins the *interop bytes* that a peer implementation must agree on — exact frame
//! type prefixes (`0x30`/`0x31`), the optional length field, the varint length
//! size-class boundary, multi-frame framing, the "consume to end of packet"
//! semantics of the length-less form, `encoded_size()` consistency, and the full
//! decode error matrix.
//!
//! Run with: `cargo test -p asupersync --test atp_datagram_frame_rfc9221_conformance`.

use asupersync::bytes::{Bytes, BytesMut};
use asupersync::net::atp::datagram::{DatagramError, DatagramFrame, DatagramFrameType};
use asupersync::types::outcome::Outcome;

fn encode(frame: &DatagramFrame) -> Vec<u8> {
    let mut buf = BytesMut::new();
    frame.encode(&mut buf).unwrap();
    buf.as_ref().to_vec()
}

fn decode(bytes: &[u8], max_size: usize) -> Outcome<DatagramFrame, DatagramError> {
    let mut buf = BytesMut::from(bytes);
    DatagramFrame::decode(&mut buf, max_size)
}

/// The RFC 9221 frame type code points are exactly `0x30` / `0x31`.
#[test]
fn frame_type_code_points_are_rfc9221() {
    assert_eq!(DatagramFrameType::Datagram as u64, 0x30);
    assert_eq!(DatagramFrameType::DatagramWithLength as u64, 0x31);
}

/// A length-less frame is `0x30` followed by the raw payload (it runs to the end
/// of the packet).
#[test]
fn wire_bytes_without_length_is_type_then_payload() {
    let frame = DatagramFrame::without_length(Bytes::from(vec![0xAA, 0xBB, 0xCC]));
    assert_eq!(encode(&frame), vec![0x30, 0xAA, 0xBB, 0xCC]);

    // Empty payload is the bare type byte.
    let empty = DatagramFrame::without_length(Bytes::from(Vec::new()));
    assert_eq!(encode(&empty), vec![0x30]);
}

/// A length-prefixed frame is `0x31`, a varint length, then the payload.
#[test]
fn wire_bytes_with_length_is_type_len_payload() {
    let frame = DatagramFrame::with_length(Bytes::from(vec![0xAA, 0xBB, 0xCC]));
    // length 3 fits a 1-byte varint whose value byte is 0x03.
    assert_eq!(encode(&frame), vec![0x31, 0x03, 0xAA, 0xBB, 0xCC]);

    // Empty payload still carries the explicit zero length.
    let empty = DatagramFrame::with_length(Bytes::from(Vec::new()));
    assert_eq!(encode(&empty), vec![0x31, 0x00]);
}

/// `encoded_size()` must equal the real encoded length for both forms across a
/// range of payload sizes (a metamorphic consistency check).
#[test]
fn encoded_size_matches_real_length() {
    for size in [0usize, 1, 2, 63, 64, 300] {
        for with_length in [false, true] {
            let frame = DatagramFrame::new(Bytes::from(vec![0x5A; size]), with_length);
            assert_eq!(
                encode(&frame).len(),
                frame.encoded_size(),
                "size={size} with_length={with_length}",
            );
        }
    }
}

/// The varint length field grows from one byte to two as the payload crosses 63
/// → 64 bytes; the frame must encode and round-trip on both sides of the edge.
#[test]
fn varint_length_size_class_boundary() {
    let f63 = DatagramFrame::with_length(Bytes::from(vec![0u8; 63]));
    assert_eq!(
        f63.encoded_size(),
        1 + 1 + 63,
        "type + 1-byte len + 63 payload"
    );
    let f64 = DatagramFrame::with_length(Bytes::from(vec![0u8; 64]));
    assert_eq!(
        f64.encoded_size(),
        1 + 2 + 64,
        "type + 2-byte len + 64 payload"
    );

    for frame in [f63, f64] {
        let bytes = encode(&frame);
        assert_eq!(bytes.len(), frame.encoded_size());
        let mut buf = BytesMut::from(bytes.as_slice());
        let decoded = DatagramFrame::decode(&mut buf, 4096).unwrap();
        assert_eq!(decoded.payload_len(), frame.payload_len());
        assert!(buf.is_empty());
    }
}

/// `decode(encode(frame)) == frame` for both forms across a payload matrix.
#[test]
fn round_trip_matrix_is_identity() {
    for size in [0usize, 1, 2, 63, 64, 255, 300] {
        for with_length in [false, true] {
            let data: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
            let payload = Bytes::from(data);
            let frame = DatagramFrame::new(payload.clone(), with_length);
            let mut buf = BytesMut::from(encode(&frame).as_slice());
            let decoded = DatagramFrame::decode(&mut buf, 4096).unwrap();
            assert_eq!(decoded.frame_type, frame.frame_type);
            assert_eq!(
                decoded.payload(),
                &payload,
                "size={size} with_length={with_length}"
            );
            assert!(buf.is_empty());
        }
    }
}

/// The length-less form consumes everything remaining in the buffer — which is
/// exactly why RFC 9221 only permits it as the last frame in a packet.
#[test]
fn without_length_consumes_rest_of_buffer() {
    let mut buf = BytesMut::from([0x30u8, 0x01, 0x02, 0x03, 0x04].as_slice());
    let decoded = DatagramFrame::decode(&mut buf, 1024).unwrap();
    assert_eq!(decoded.frame_type, DatagramFrameType::Datagram);
    assert_eq!(decoded.payload().as_ref(), &[0x01, 0x02, 0x03, 0x04]);
    assert!(buf.is_empty());
}

/// Two length-prefixed frames packed back-to-back decode in order, each bounded
/// by its own length field.
#[test]
fn multiple_with_length_frames_decode_sequentially() {
    let mut buf = BytesMut::new();
    DatagramFrame::with_length(Bytes::from(vec![0x11, 0x22]))
        .encode(&mut buf)
        .unwrap();
    DatagramFrame::with_length(Bytes::from(vec![0x33]))
        .encode(&mut buf)
        .unwrap();

    let first = DatagramFrame::decode(&mut buf, 1024).unwrap();
    assert_eq!(first.payload().as_ref(), &[0x11, 0x22]);
    let second = DatagramFrame::decode(&mut buf, 1024).unwrap();
    assert_eq!(second.payload().as_ref(), &[0x33]);
    assert!(buf.is_empty());
}

/// The decode error matrix: empty input, unknown type, truncated length,
/// truncated payload.
#[test]
fn decode_rejects_malformed_frames() {
    assert!(matches!(
        decode(&[], 1024),
        Outcome::Err(DatagramError::InvalidFrame(_))
    ));
    // 0x32 is not a DATAGRAM frame type.
    assert!(matches!(
        decode(&[0x32, 0x01], 1024),
        Outcome::Err(DatagramError::InvalidFrame(_))
    ));
    // Length-prefixed type with no length field following it.
    assert!(matches!(
        decode(&[0x31], 1024),
        Outcome::Err(DatagramError::InvalidFrame(_))
    ));
    // Declares 5 payload bytes but only one is present.
    assert!(matches!(
        decode(&[0x31, 0x05, 0xAA], 1024),
        Outcome::Err(DatagramError::InvalidFrame(_))
    ));
}

/// Both forms enforce `max_size`, reporting the offending size and the cap. For
/// the length-prefixed form the declared length is rejected before the buffer is
/// even consulted.
#[test]
fn decode_enforces_max_size() {
    assert!(matches!(
        decode(&[0x30, 0xAA, 0xBB, 0xCC], 2),
        Outcome::Err(DatagramError::PayloadTooLarge { size: 3, max: 2 })
    ));
    assert!(matches!(
        decode(&[0x31, 0x05, 0xAA], 2),
        Outcome::Err(DatagramError::PayloadTooLarge { size: 5, max: 2 })
    ));
}
