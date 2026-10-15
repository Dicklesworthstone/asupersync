//! Regression tests for protobuf varint length validation through the gRPC codec.

use asupersync::bytes::Bytes;
use asupersync::grpc::codec::Codec;
use asupersync::grpc::protobuf::{ProstCodec, ProtobufError};

#[derive(Clone, PartialEq, prost::Message)]
struct TestMessage {
    #[prost(uint64, tag = "1")]
    value: u64,
}

fn decode_payload(payload: &[u8]) -> Result<TestMessage, ProtobufError> {
    let mut codec: ProstCodec<TestMessage, TestMessage> = ProstCodec::new();
    codec.decode(&Bytes::copy_from_slice(payload))
}

fn assert_invalid_varint(payload: &[u8]) {
    let err = decode_payload(payload).expect_err("oversized varint must be rejected");
    let message = err.to_string();
    assert!(
        message.contains("invalid varint"),
        "expected invalid varint error, got {message:?}"
    );
}

#[test]
fn ten_byte_u64_max_varint_is_accepted() {
    let decoded = decode_payload(&[
        0x08, // field 1, varint wire type
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x01,
    ])
    .expect("u64::MAX uses the maximum valid 10-byte varint");

    assert_eq!(decoded.value, u64::MAX);
}

#[test]
fn ten_byte_varint_with_bits_above_u64_is_rejected() {
    assert_invalid_varint(&[
        0x08, // field 1, varint wire type
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x02,
    ]);
}

#[test]
fn eleven_byte_varint_is_rejected() {
    assert_invalid_varint(&[
        0x08, // field 1, varint wire type
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x01,
    ]);
}

#[test]
fn unterminated_ten_byte_varint_is_rejected() {
    assert_invalid_varint(&[
        0x08, // field 1, varint wire type
        0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80,
    ]);
}

#[test]
fn codec_size_limit_rejects_before_decoding() {
    let mut codec: ProstCodec<TestMessage, TestMessage> = ProstCodec::with_max_size(1);
    let result = codec.decode(&Bytes::from_static(&[0x08, 0x01]));

    match result {
        Err(ProtobufError::MessageTooLarge { size, limit }) => {
            assert_eq!(size, 2);
            assert_eq!(limit, 1);
        }
        other => panic!("expected size-limit error before prost decode, got {other:?}"),
    }
}
