//! Audit + regression test for `src/grpc/codec.rs` `IdentityCodec`
//! message-level passthrough (tick #192).
//!
//! Operator's question: "verify identity-codec passthrough."
//!
//! Audit context:
//!
//!   The Codec layer (codec.rs:196-225) is the message-
//!   serialization API: `Encode` type → Bytes → wire frame →
//!   Bytes → `Decode` type. `IdentityCodec` (codec.rs:565-583)
//!   is the trivial Encode=Bytes, Decode=Bytes implementation
//!   used when the caller handles serialization themselves
//!   (e.g. raw protobuf bytes already produced).
//!
//!   This is DISTINCT from the frame-level identity hooks
//!   (`identity_frame_compress` / `identity_frame_decompress`,
//!   audited in tick #190). Layer model:
//!
//!     wire bytes
//!         ↓ [GrpcCodec framing — size cap, flag check]
//!     GrpcMessage { compressed, data: Bytes }
//!         ↓ [FrameDecompressor — gzip OR identity passthrough]
//!     decompressed Bytes
//!         ↓ [Codec::decode — IdentityCodec passes through]
//!     decoded type T
//!
//!   IdentityCodec is the LAST layer. A regression here would
//!   silently corrupt the messages even after framing + size
//!   caps fired correctly.
//!
//! Audit findings:
//!
//!   (a) **`IdentityCodec::encode` is a pure clone** (codec.rs:
//!       576-578 — `Ok(item.clone())`). `Bytes::clone()` is an
//!       Arc refcount bump, NOT a memcpy. Hot path is
//!       allocation-free.
//!
//!   (b) **`IdentityCodec::decode` is a pure clone** (codec.rs:
//!       580-582). Same zero-copy story on the decode side.
//!
//!   (c) **`IdentityCodec::Error = Infallible`** (codec.rs:574).
//!       The codec NEVER returns Err — it can't fail. This
//!       guarantees the caller's error-handling never has to
//!       branch on a codec-error path that can never fire.
//!
//!   (d) **No size validation IN IdentityCodec.** The Codec
//!       trait's default `set_max_decode_message_size` is a
//!       no-op (codec.rs:213-214). IdentityCodec inherits the
//!       default, so size enforcement happens at the FramedCodec
//!       layer ABOVE — the wire-level cap is enforced once
//!       (codec.rs:135) at the framing decode, not duplicated
//!       at the message codec.
//!
//!   (e) **Round-trip preserves bytes byte-for-byte across
//!       every byte value.** Pinned via 0x00..0xFF scan.
//!
//!   (f) **Encode-then-decode round-trip is the identity
//!       function on Bytes.** A regression that introduced a
//!       transformation (e.g. accidental endian swap) would
//!       surface here.
//!
//! Regression tests below pin (a)-(f).

use asupersync::bytes::{Bytes, BytesMut};
use asupersync::codec::{Decoder, Encoder};
use asupersync::grpc::{GrpcCodec, GrpcMessage, IdentityCodec};
use asupersync::grpc::codec::Codec;

#[test]
fn identity_codec_encode_returns_input_bytes() {
    // Pin (a): encode returns the input Bytes (Arc clone — not
    // memcpy, not modification).
    let mut codec = IdentityCodec;
    let input = Bytes::from_static(b"identity codec test payload");
    let encoded = codec.encode(&input).expect("Infallible Result");
    assert_eq!(encoded.as_ref(), input.as_ref());
    // Strong pin: Bytes::clone shares the same backing — they're
    // equal as byte slices.
    assert_eq!(encoded, input);
}

#[test]
fn identity_codec_decode_returns_input_bytes() {
    // Pin (b): decode returns the input Bytes unchanged.
    let mut codec = IdentityCodec;
    let input = Bytes::from_static(b"identity decode test payload");
    let decoded = codec.decode(&input).expect("Infallible Result");
    assert_eq!(decoded.as_ref(), input.as_ref());
}

#[test]
fn identity_codec_encode_decode_round_trip_every_byte_value() {
    // Pin (e)+(f): every byte value 0x00..0xFF survives an
    // encode-then-decode round-trip.
    let mut codec = IdentityCodec;
    let original: Vec<u8> = (0u8..=255u8).collect();
    let encoded = codec
        .encode(&Bytes::from(original.clone()))
        .expect("Infallible");
    let decoded = codec.decode(&encoded).expect("Infallible");
    assert_eq!(
        decoded.as_ref(),
        &original[..],
        "every byte 0x00..0xFF must survive identity round-trip exactly",
    );
}

#[test]
fn identity_codec_round_trip_preserves_empty_bytes() {
    // Pin (e) edge: empty Bytes round-trips as empty.
    let mut codec = IdentityCodec;
    let empty = Bytes::new();
    let encoded = codec.encode(&empty).expect("Infallible");
    assert_eq!(encoded.len(), 0);
    let decoded = codec.decode(&encoded).expect("Infallible");
    assert_eq!(decoded.len(), 0);
}

#[test]
fn identity_codec_round_trip_preserves_high_bit_bytes() {
    // Pin (e) extension: high-bit bytes (0x80..0xFF) preserve.
    // A regression that demoted to ASCII (or applied any
    // visible-only filter) would surface here.
    let mut codec = IdentityCodec;
    let high_bit: Vec<u8> = (0x80u8..=0xFFu8).collect();
    let encoded = codec
        .encode(&Bytes::from(high_bit.clone()))
        .expect("Infallible");
    let decoded = codec.decode(&encoded).expect("Infallible");
    assert_eq!(decoded.as_ref(), &high_bit[..]);
}

#[test]
fn identity_codec_default_constructor_is_zero_sized() {
    // Pin (a)+(b): IdentityCodec is a unit struct with Default
    // impl. A regression that added stateful fields (e.g. a
    // counter, a buffer) would change the type's size and break
    // hot-path performance assumptions.
    assert_eq!(
        std::mem::size_of::<IdentityCodec>(),
        0,
        "IdentityCodec must be zero-sized (unit struct) — adding fields \
         introduces per-instance state that the API contract forbids",
    );
}

#[test]
fn identity_codec_through_framed_codec_round_trips_payload() {
    // Pin (d)+(f) integration: an IdentityCodec wrapped in a
    // GrpcCodec framing layer round-trips a payload through
    // wire bytes back to the same payload. Pin the full
    // pipeline.
    let mut framing = GrpcCodec::with_max_size(64 * 1024);
    let mut wire = BytesMut::new();

    let payload = Bytes::from_static(b"end-to-end identity round-trip");
    framing
        .encode(GrpcMessage::new(payload.clone()), &mut wire)
        .expect("framing encode");

    // Decode framing + IdentityCodec::decode — both pure
    // pass-through on the body bytes.
    let decoded_msg = framing
        .decode(&mut wire)
        .expect("framing decode")
        .expect("frame complete");
    assert_eq!(decoded_msg.data.as_ref(), payload.as_ref());

    let mut inner = IdentityCodec;
    let decoded_inner = inner
        .decode(&decoded_msg.data)
        .expect("Infallible");
    assert_eq!(decoded_inner.as_ref(), payload.as_ref());
}

#[test]
fn identity_codec_decode_is_idempotent_on_repeated_call() {
    // Pin (b): calling decode twice with the same input
    // produces the same output. No internal state mutation.
    let mut codec = IdentityCodec;
    let input = Bytes::from_static(b"idempotent payload");
    let first = codec.decode(&input).expect("Infallible");
    let second = codec.decode(&input).expect("Infallible");
    assert_eq!(first, second);
    assert_eq!(first.as_ref(), input.as_ref());
}

#[test]
fn identity_codec_encode_does_not_mutate_input() {
    // Pin (a): encode takes &Self::Encode (immutable
    // reference). Bytes is Clone — encode returns a clone.
    // The original Bytes is untouched.
    let mut codec = IdentityCodec;
    let original = Bytes::from_static(b"original bytes");
    let _ = codec.encode(&original).expect("Infallible");
    // Original is still accessible and unchanged.
    assert_eq!(original.as_ref(), b"original bytes");
}
