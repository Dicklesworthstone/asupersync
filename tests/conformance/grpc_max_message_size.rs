use asupersync::bytes::{Bytes, BytesMut};
use asupersync::codec::{Decoder, Encoder};
use asupersync::grpc::{
    Code, DEFAULT_MAX_MESSAGE_SIZE, FramedCodec, GrpcCodec, GrpcError, GrpcMessage, IdentityCodec,
    Server,
};

#[test]
fn grpc_defaults_to_4_mib_limits_for_codec_and_server() {
    assert_eq!(
        DEFAULT_MAX_MESSAGE_SIZE,
        4 * 1024 * 1024,
        "the canonical gRPC default is 4 MiB"
    );

    let codec = GrpcCodec::new();
    assert_eq!(codec.max_encode_message_size(), DEFAULT_MAX_MESSAGE_SIZE);
    assert_eq!(codec.max_decode_message_size(), DEFAULT_MAX_MESSAGE_SIZE);

    let server = Server::builder().build();
    let config = server.config();
    assert_eq!(config.max_recv_message_size, DEFAULT_MAX_MESSAGE_SIZE);
    assert_eq!(config.max_send_message_size, DEFAULT_MAX_MESSAGE_SIZE);
}

#[test]
fn grpc_codec_enforces_directional_message_caps() {
    let mut wire = BytesMut::new();
    let encode_err = GrpcCodec::with_message_size_limits(3, 32)
        .encode(GrpcMessage::new(Bytes::from_static(b"four")), &mut wire)
        .expect_err("oversized outbound payload must be rejected");
    assert!(matches!(encode_err, GrpcError::MessageTooLarge));
    assert_eq!(
        encode_err.into_status().code(),
        Code::ResourceExhausted,
        "oversized outbound payloads must surface RESOURCE_EXHAUSTED"
    );

    let mut inbound = BytesMut::from(&b"\x00\x00\x00\x00\x04four"[..]);
    let decode_err = GrpcCodec::with_message_size_limits(32, 3)
        .decode(&mut inbound)
        .expect_err("oversized inbound payload must be rejected");
    assert!(matches!(decode_err, GrpcError::MessageTooLarge));
    assert_eq!(
        decode_err.into_status().code(),
        Code::ResourceExhausted,
        "oversized inbound payloads must surface RESOURCE_EXHAUSTED"
    );
}

#[test]
fn server_builder_preserves_custom_send_and_receive_caps() {
    let server = Server::builder()
        .max_recv_message_size(1024)
        .max_send_message_size(2048)
        .build();
    let config = server.config();

    assert_eq!(config.max_recv_message_size, 1024);
    assert_eq!(config.max_send_message_size, 2048);
}

#[test]
fn framed_codec_enforces_directional_caps_too() {
    let mut send_wire = BytesMut::new();
    let send_err = FramedCodec::with_message_size_limits(IdentityCodec, 3, 32)
        .encode_message(&Bytes::from_static(b"four"), &mut send_wire)
        .expect_err("framed codec must reject outbound payloads above max_send_message_size");
    assert!(matches!(send_err, GrpcError::MessageTooLarge));

    let mut inbound_wire = BytesMut::new();
    GrpcCodec::with_message_size_limits(32, 32)
        .encode(
            GrpcMessage::new(Bytes::from_static(b"four")),
            &mut inbound_wire,
        )
        .expect("reference frame encodes");

    let receive_err = FramedCodec::with_message_size_limits(IdentityCodec, 32, 3)
        .decode_message(&mut inbound_wire)
        .expect_err("framed codec must reject inbound payloads above max_recv_message_size");
    assert!(matches!(receive_err, GrpcError::MessageTooLarge));
}
