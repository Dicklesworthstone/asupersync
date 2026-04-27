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
fn framed_codec_identity_compression_round_trips_when_enabled() {
    let payload = Bytes::from_static(b"identity-compressed");
    let mut encoder = FramedCodec::new(IdentityCodec).with_identity_frame_codec();
    let mut decoder = FramedCodec::new(IdentityCodec).with_identity_frame_codec();
    let mut wire = BytesMut::new();

    encoder
        .encode_message(&payload, &mut wire)
        .expect("identity-compressed frame must encode");

    assert_eq!(
        wire[0], 1,
        "identity frame codec must still set the compressed flag"
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
    let mut encoder = FramedCodec::new(IdentityCodec).with_identity_frame_codec();
    let mut decoder = FramedCodec::new(IdentityCodec);
    let mut wire = BytesMut::new();

    encoder
        .encode_message(&payload, &mut wire)
        .expect("identity-compressed frame must encode");

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
