//! RFC 9221 QUIC DATAGRAM frame wire-format conformance (`b0k8qo.1.2` / A2).
//!
//! The DATAGRAM frame codec (`src/net/atp/protocol/quic_frames.rs`) carries the
//! production ATP datagram data plane: every RaptorQ symbol the QUIC transport
//! sprays rides a `QuicFrame::Datagram`. RFC 9221 §4 defines two on-wire forms:
//!
//! - **type `0x30`** — *no* length field; the payload runs to the end of the
//!   packet, so a `0x30` datagram can only ever be the packet's last frame;
//! - **type `0x31`** — an explicit length prefix, making the frame
//!   *self-delimiting* and therefore safe to place before any other frame.
//!
//! Choosing the wrong type is a silent corruption: a `0x30` datagram followed by
//! another frame would swallow that frame's bytes as datagram payload, and a
//! receiver would mis-parse the rest of the packet. The production encoder
//! defends against this by **always** emitting the self-delimiting `0x31` form
//! (it never bets on being last), while the decoder still honors both forms it
//! may receive from a conforming peer.
//!
//! These tests pin that contract from **outside the crate**, exercising only the
//! public `QuicFrame` encode/decode surface, so the guarantees survive even when
//! the in-crate `#[cfg(test)]` unit binary is red because an unrelated peer
//! module fails to compile. They assert the RFC 9221 wire invariants directly:
//!
//! 1. the encoder always selects the self-delimiting `0x31` type;
//! 2. a length-prefixed datagram never swallows trailing frames (the
//!    self-delimiting property, end to end through a multi-frame packet);
//! 3. a hand-built `0x30` datagram consumes to the end of the buffer (the
//!    decoder honors the RFC §4 no-length form);
//! 4. encode→decode is byte-identical over a payload corpus (empty .. 4 KiB);
//! 5. a length-prefixed datagram declaring more bytes than are present fails
//!    closed with `UnexpectedEof` — no panic, no short/garbage frame;
//! 6. metamorphic: a datagram's decoded payload is invariant under whatever
//!    frames surround it, and no surrounding frame is lost or spuriously added.
//!
//! Everything here is deterministic and oracle-free: the relations hold by RFC
//! construction, so every assertion is replay-exact with no seeded randomness.

#![allow(missing_docs)]

use asupersync::bytes::{Bytes, BytesMut};
use asupersync::net::atp::protocol::quic_frames::{QuicFrame, QuicFrameError};

// ── Wire helpers (public API only) ──────────────────────────────────────────

/// Encode a single frame into its wire bytes.
fn encode_one(frame: &QuicFrame) -> BytesMut {
    let mut buf = BytesMut::new();
    frame.encode(&mut buf).expect("frame encodes");
    buf
}

/// Encode a sequence of frames back-to-back, exactly as a packet payload carries
/// them.
fn encode_all(frames: &[QuicFrame]) -> BytesMut {
    let mut buf = BytesMut::new();
    for frame in frames {
        frame.encode(&mut buf).expect("frame encodes");
    }
    buf
}

/// Decode every frame out of a wire buffer in order; `decode` returns `Ok(None)`
/// once the buffer is exhausted, which terminates the walk.
fn decode_all(wire: BytesMut) -> Vec<QuicFrame> {
    let mut reader = wire.freeze().reader();
    let mut frames = Vec::new();
    while let Some(frame) = QuicFrame::decode(&mut reader).expect("frame decodes") {
        frames.push(frame);
    }
    frames
}

fn datagram(payload: &[u8]) -> QuicFrame {
    QuicFrame::Datagram {
        data: Bytes::copy_from_slice(payload),
    }
}

fn datagram_payload(frame: &QuicFrame) -> &[u8] {
    match frame {
        QuicFrame::Datagram { data } => data.as_ref(),
        other => panic!("expected a DATAGRAM frame, got {other:?}"),
    }
}

// ── (1) The encoder always emits the self-delimiting 0x31 type ──────────────

/// The production encoder must never bet on a datagram being the packet's last
/// frame: it always sets the LEN bit (type `0x31`), so the frame is
/// self-delimiting and safe to precede any other frame.
#[test]
fn encoder_emits_self_delimiting_len_bit_for_every_payload() {
    for size in [0usize, 1, 63, 64, 255, 1000] {
        let payload = vec![0xA5u8; size];
        let wire = encode_one(&datagram(&payload));
        assert_eq!(
            wire.as_ref()[0],
            0x31,
            "encoder must emit the self-delimiting LEN-bit type (0x31), never the \
             run-to-end type (0x30), so a DATAGRAM is safe before other frames \
             (payload size = {size})"
        );
    }
}

// ── (2) A 0x31 datagram never swallows trailing frames ──────────────────────

/// End to end through a multi-frame packet: a length-prefixed datagram is
/// self-delimiting, so frames that follow it decode intact and in order. This is
/// the property a `0x30` would violate.
#[test]
fn length_prefixed_datagram_never_swallows_trailing_frames() {
    let symbol_a = b"raptorq-symbol-A".to_vec();
    let symbol_b = b"raptorq-symbol-B-with-a-longer-payload".to_vec();
    let frames = vec![
        datagram(&symbol_a),
        QuicFrame::Ping,
        datagram(&symbol_b),
        QuicFrame::Ping,
    ];

    let decoded = decode_all(encode_all(&frames));

    assert_eq!(
        decoded.len(),
        4,
        "every frame must survive: a self-delimiting datagram never eats trailing frames"
    );
    assert_eq!(datagram_payload(&decoded[0]), symbol_a.as_slice());
    assert_eq!(decoded[1], QuicFrame::Ping);
    assert_eq!(datagram_payload(&decoded[2]), symbol_b.as_slice());
    assert_eq!(decoded[3], QuicFrame::Ping);
}

// ── (3) A 0x30 datagram runs to the end of the buffer (RFC 9221 §4) ─────────

/// The decoder must honor the no-length form a conforming peer may send: type
/// `0x30` carries its payload to the end of the packet. Hand-built on the wire
/// because the production encoder never emits `0x30`.
#[test]
fn no_length_datagram_consumes_to_end_of_buffer() {
    let payload = b"tail-bytes-all-the-way-to-the-end";
    let mut wire = BytesMut::new();
    wire.put_slice(&[0x30]); // single-byte varint frame type, LEN bit clear
    wire.put_slice(payload);

    let decoded = decode_all(wire);

    assert_eq!(
        decoded.len(),
        1,
        "a 0x30 datagram is necessarily the last frame — it consumes the rest of the buffer"
    );
    assert_eq!(datagram_payload(&decoded[0]), &payload[..]);
}

// ── (4) Encode→decode identity over a payload corpus ────────────────────────

/// Round-trip identity across boundary payload sizes, including the empty
/// payload and sizes that straddle the 1-byte/2-byte QUIC varint length
/// boundary (63 → 64, 255 → 256).
#[test]
fn roundtrip_identity_over_payload_corpus() {
    let corpus: Vec<Vec<u8>> = vec![
        Vec::new(),
        vec![0x00],
        vec![0xFF; 63],
        vec![0xFF; 64],
        (0u8..=254).collect(),
        vec![0x5Au8; 256],
        vec![0x5Au8; 4096],
    ];

    for payload in corpus {
        let decoded = decode_all(encode_one(&datagram(&payload)));
        assert_eq!(
            decoded.len(),
            1,
            "exactly one frame must round-trip and the buffer must be fully consumed \
             (payload len = {})",
            payload.len()
        );
        assert_eq!(
            datagram_payload(&decoded[0]),
            payload.as_slice(),
            "payload must round-trip byte-identical (len = {})",
            payload.len()
        );
    }
}

// ── (5) A truncated length-prefixed datagram fails closed ───────────────────

/// A `0x31` datagram declaring a length longer than the bytes actually present
/// must fail closed with `UnexpectedEof` — never panic and never surface a
/// short/garbage frame. Hand-built because the production encoder always writes
/// a length that matches the payload.
#[test]
fn truncated_length_prefixed_datagram_fails_closed() {
    let mut wire = BytesMut::new();
    // Type 0x31, then a 1-byte QUIC varint length of 20 (20 < 64 ⇒ the byte is
    // the value), but only 15 payload bytes follow.
    wire.put_slice(&[0x31, 20]);
    wire.put_slice(&[0xABu8; 15]);

    let mut reader = wire.freeze().reader();
    let result = QuicFrame::decode(&mut reader);

    assert!(
        matches!(result, Err(QuicFrameError::UnexpectedEof)),
        "a length-prefixed datagram whose declared length exceeds the buffer must \
         fail closed with UnexpectedEof, got {result:?}"
    );
}

// ── (6) Metamorphic: payload invariant under surrounding frame context ──────

/// A datagram's decoded payload depends only on the datagram itself, never on
/// the frames that surround it (because the encoder is self-delimiting). Across
/// four arrangements of the *same* payload, the recovered datagram bytes are
/// identical and no surrounding frame is lost or spuriously added.
#[test]
fn datagram_payload_is_invariant_under_surrounding_frame_context() {
    let payload = b"metamorphic-symbol-payload-0xC0FFEE".to_vec();
    let contexts: Vec<Vec<QuicFrame>> = vec![
        vec![datagram(&payload)],
        vec![QuicFrame::Ping, datagram(&payload)],
        vec![QuicFrame::Ping, datagram(&payload), QuicFrame::Ping],
        vec![datagram(&payload), QuicFrame::Ping, QuicFrame::Ping],
    ];

    for context in contexts {
        let expected_len = context.len();
        let decoded = decode_all(encode_all(&context));
        assert_eq!(
            decoded.len(),
            expected_len,
            "no frame may be lost or spuriously added by surrounding context"
        );

        let recovered = decoded
            .iter()
            .find(|frame| matches!(frame, QuicFrame::Datagram { .. }))
            .expect("a datagram is present in every context");
        assert_eq!(
            datagram_payload(recovered),
            payload.as_slice(),
            "the decoded datagram payload must be invariant under surrounding frames"
        );
    }
}
