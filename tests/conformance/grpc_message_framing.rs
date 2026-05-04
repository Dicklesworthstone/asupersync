use asupersync::bytes::{Bytes, BytesMut};
use asupersync::codec::{Decoder, Encoder};
use asupersync::grpc::{FramedCodec, GrpcCodec, GrpcError, GrpcMessage, IdentityCodec};

#[test]
fn grpc_frame_prefix_is_flag_plus_big_endian_length() {
    let mut codec = GrpcCodec::new();
    let mut wire = BytesMut::new();

    codec
        .encode(GrpcMessage::new(Bytes::from_static(b"hello")), &mut wire)
        .expect("encoding a small frame must succeed");

    assert_eq!(wire[0], 0, "identity frames must clear the compressed flag");
    assert_eq!(
        &wire[1..5],
        &[0, 0, 0, 5],
        "payload length must be stored as a 4-byte big-endian integer"
    );
    assert_eq!(&wire[5..], b"hello");
}

#[test]
fn grpc_compressed_flag_round_trips_without_mutating_payload() {
    let mut codec = GrpcCodec::new();
    let mut wire = BytesMut::new();

    codec
        .encode(
            GrpcMessage::compressed(Bytes::from_static(b"zip")),
            &mut wire,
        )
        .expect("compressed-flag frame must encode");

    assert_eq!(wire[0], 1, "compressed frames must set bit 0");

    let decoded = codec
        .decode(&mut wire)
        .expect("decode should succeed")
        .expect("full frame should be available");

    assert!(decoded.compressed, "compressed flag must survive decode");
    assert_eq!(decoded.data.as_ref(), b"zip");
}

#[test]
fn grpc_codec_rejects_invalid_compression_flag_values() {
    let mut codec = GrpcCodec::new();
    let mut wire = BytesMut::from(&b"\x02\x00\x00\x00\x00"[..]);

    let err = codec
        .decode(&mut wire)
        .expect_err("flag values other than 0 or 1 must be rejected");

    match err {
        GrpcError::Protocol(message) => {
            assert!(
                message.contains("invalid gRPC compression flag"),
                "unexpected protocol error: {message}"
            );
        }
        other => panic!("expected protocol error, got {other:?}"),
    }
}

#[test]
fn grpc_codec_waits_for_full_invalid_flag_frame_like_grpc_go() {
    let mut codec = GrpcCodec::new();
    let mut wire = BytesMut::from(&b"\x02\x00\x00\x00\x03a"[..]);

    let pending = codec
        .decode(&mut wire)
        .expect("grpc-go parity: invalid flag is checked after the full frame is read");
    assert!(
        pending.is_none(),
        "partial invalid frames should stay pending until the declared body arrives"
    );
    assert_eq!(wire.as_ref(), b"\x02\x00\x00\x00\x03a");

    wire.extend_from_slice(b"bc");
    let err = codec
        .decode(&mut wire)
        .expect_err("full invalid frame must be rejected once the declared body is present");

    match err {
        GrpcError::Protocol(message) => {
            assert!(
                message.contains("invalid gRPC compression flag: 2"),
                "unexpected protocol error: {message}"
            );
        }
        other => panic!("expected protocol error, got {other:?}"),
    }
    assert!(
        wire.is_empty(),
        "grpc-go consumes the invalid frame before surfacing the payload-format error"
    );
}

#[test]
fn framed_codec_identity_hooks_emit_bare_noop_wire() {
    let payload = Bytes::from_static(b"identity-noop");
    let mut encoder = FramedCodec::new(IdentityCodec).with_identity_frame_codec();
    let mut decoder = FramedCodec::new(IdentityCodec);
    let mut wire = BytesMut::new();

    encoder
        .encode_message(&payload, &mut wire)
        .expect("identity no-op frame must encode");

    assert_eq!(
        wire[0], 0,
        "identity frame codec is a no-op and must clear the compressed flag"
    );

    let decoded = decoder
        .decode_message(&mut wire)
        .expect("decode should succeed")
        .expect("frame should be available");

    assert_eq!(decoded, payload);
}

#[test]
fn framed_codec_rejects_compressed_frames_without_decompressor() {
    let payload = Bytes::from_static(b"negotiation required");
    let mut decoder = FramedCodec::new(IdentityCodec);
    let mut wire = BytesMut::new();

    wire.extend_from_slice(&[0x01]);
    wire.extend_from_slice(
        &u32::try_from(payload.len())
            .expect("fixture length fits u32")
            .to_be_bytes(),
    );
    wire.extend_from_slice(&payload);

    let err = decoder
        .decode_message(&mut wire)
        .expect_err("compressed frames without a negotiated decompressor must fail");

    match err {
        GrpcError::Compression(message) => {
            assert!(
                message.contains("no frame decompressor configured"),
                "unexpected compression error: {message}"
            );
        }
        other => panic!("expected compression error, got {other:?}"),
    }
}
