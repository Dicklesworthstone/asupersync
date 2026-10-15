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
fn grpc_codec_accepts_messages_exactly_at_directional_caps() {
    let exact_payload = Bytes::from_static(b"four");
    let mut wire = BytesMut::new();

    GrpcCodec::with_message_size_limits(exact_payload.len(), 32)
        .encode(GrpcMessage::new(exact_payload.clone()), &mut wire)
        .expect("payload exactly at max_send_message_size must encode");

    assert_eq!(
        &wire[1..5],
        &(exact_payload.len() as u32).to_be_bytes(),
        "encoded length prefix must match the exact-limit payload"
    );

    let mut decoder = GrpcCodec::with_message_size_limits(32, exact_payload.len());
    let decoded = <GrpcCodec as Decoder>::decode(&mut decoder, &mut wire)
        .expect("payload exactly at max_recv_message_size must decode")
        .expect("full exact-limit frame should be available");

    assert!(!decoded.compressed);
    assert_eq!(decoded.data, exact_payload);
    assert!(
        wire.is_empty(),
        "exact-limit frame should be fully consumed after successful decode"
    );
}

#[test]
fn grpc_codec_rejects_oversized_declared_length_before_body_arrives() {
    let mut wire = BytesMut::from(b"\x00\x00\x00\x00\x04".as_slice());

    let mut decoder = GrpcCodec::with_message_size_limits(32, 3);
    let err = <GrpcCodec as Decoder>::decode(&mut decoder, &mut wire)
        .expect_err("declared inbound length above max_recv_message_size must fail immediately");

    assert!(matches!(err, GrpcError::MessageTooLarge));
    assert_eq!(err.into_status().code(), Code::ResourceExhausted);
    assert_eq!(
        wire.as_ref(),
        b"\x00\x00\x00\x00\x04",
        "oversized length-prefix rejection must not consume bytes before the caller handles the error"
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

#[test]
fn grpc_go_max_decoded_len_boundary_accepts_exact_decompression_then_rejects_plus_one() {
    fn passthrough_compress(input: Bytes) -> Result<Bytes, GrpcError> {
        Ok(input)
    }

    fn grpc_go_style_boundary_decompress(
        input: Bytes,
        max_size: usize,
    ) -> Result<Bytes, GrpcError> {
        let expanded = match input.as_ref() {
            b"eq" => vec![b'e'; max_size],
            b"gt" => vec![b'g'; max_size.saturating_add(1)],
            other => other.to_vec(),
        };
        if expanded.len() > max_size {
            return Err(GrpcError::MessageTooLarge);
        }
        Ok(Bytes::from(expanded))
    }

    let max_decoded_len = 8usize;
    let mut producer = GrpcCodec::with_message_size_limits(32, 32);
    let mut wire = BytesMut::new();
    producer
        .encode(
            GrpcMessage::compressed(Bytes::from_static(b"eq")),
            &mut wire,
        )
        .expect("exact-limit compressed frame should encode");
    producer
        .encode(
            GrpcMessage::compressed(Bytes::from_static(b"gt")),
            &mut wire,
        )
        .expect("limit-plus-one compressed frame should encode");

    let mut codec = FramedCodec::with_message_size_limits(IdentityCodec, 32, max_decoded_len)
        .with_frame_codec(passthrough_compress, grpc_go_style_boundary_decompress);

    let exact = codec
        .decode_message(&mut wire)
        .expect("grpc-go accepts decompressed payloads exactly at maxReceiveMessageSize")
        .expect("first compressed frame should decode");
    assert_eq!(
        exact,
        Bytes::from_static(b"eeeeeeee"),
        "exact max_decoded_len decompression must succeed"
    );

    let over = codec
        .decode_message(&mut wire)
        .expect_err("grpc-go rejects decompressed payloads above maxReceiveMessageSize");
    assert!(matches!(over, GrpcError::MessageTooLarge));
    assert_eq!(over.into_status().code(), Code::ResourceExhausted);
}
