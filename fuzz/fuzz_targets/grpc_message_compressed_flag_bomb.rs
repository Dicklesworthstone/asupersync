#![no_main]

//! gRPC compressed-flag length bomb fuzzer.
//!
//! Builds a length-prefixed gRPC message with Compressed-Flag=1 and a
//! declared MAX_INT payload length, while the actual bytes end after a tiny
//! suffix. The codec must reject from the length prefix before allocating or
//! waiting for the declared body.

use arbitrary::Arbitrary;
use asupersync::bytes::BytesMut;
use asupersync::codec::Decoder;
use asupersync::grpc::Code;
use asupersync::grpc::codec::{FramedCodec, GrpcCodec, IdentityCodec, MESSAGE_HEADER_SIZE};
use asupersync::grpc::status::GrpcError;
use libfuzzer_sys::fuzz_target;

const MAX_INT_DECLARED_LENGTH: u32 = i32::MAX as u32;
const MAX_SUFFIX_BYTES: usize = 1024;
const MAX_DECODE_LIMIT: usize = 64 * 1024;

#[derive(Debug, Arbitrary)]
struct CompressedFlagBomb {
    suffix: Vec<u8>,
    decode_limit: u16,
    variant: BombLengthVariant,
}

#[derive(Debug, Arbitrary)]
enum BombLengthVariant {
    MaxInt,
    MaxIntMinusOne,
    UnsignedMax,
}

fuzz_target!(|input: CompressedFlagBomb| {
    let decode_limit = usize::from(input.decode_limit)
        .saturating_add(1)
        .min(MAX_DECODE_LIMIT);
    let declared_len = match input.variant {
        BombLengthVariant::MaxInt => MAX_INT_DECLARED_LENGTH,
        BombLengthVariant::MaxIntMinusOne => MAX_INT_DECLARED_LENGTH - 1,
        BombLengthVariant::UnsignedMax => u32::MAX,
    };

    let suffix = &input.suffix[..input.suffix.len().min(MAX_SUFFIX_BYTES)];
    let frame = compressed_flag_bomb_frame(declared_len, suffix);
    assert!(frame.len() <= MESSAGE_HEADER_SIZE + MAX_SUFFIX_BYTES);

    assert_direct_codec_rejects_without_waiting(frame.as_slice(), decode_limit);
    assert_framed_codec_rejects_and_poison_clears(frame.as_slice(), decode_limit);
});

fn compressed_flag_bomb_frame(declared_len: u32, suffix: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(MESSAGE_HEADER_SIZE + suffix.len());
    frame.push(1);
    frame.extend_from_slice(&declared_len.to_be_bytes());
    frame.extend_from_slice(suffix);
    frame
}

fn assert_direct_codec_rejects_without_waiting(frame: &[u8], decode_limit: usize) {
    let mut codec = GrpcCodec::with_max_size(decode_limit);
    let mut buf = BytesMut::from(frame);
    let original_len = buf.len();

    match codec.decode(&mut buf) {
        Err(error) => assert_message_too_large(error, "direct compressed MAX_INT frame"),
        other => panic!("compressed MAX_INT frame must reject as MessageTooLarge, got {other:?}"),
    }

    assert_eq!(
        buf.len(),
        original_len,
        "direct codec should reject before consuming or allocating for the declared body"
    );
}

fn assert_framed_codec_rejects_and_poison_clears(frame: &[u8], decode_limit: usize) {
    let mut codec =
        FramedCodec::with_message_size_limits(IdentityCodec, decode_limit, decode_limit)
            .with_identity_frame_codec();
    let mut buf = BytesMut::from(frame);

    match codec.decode_message(&mut buf) {
        Err(error) => assert_message_too_large(error, "framed compressed MAX_INT frame"),
        other => panic!("framed codec must reject bomb frame as MessageTooLarge, got {other:?}"),
    }

    assert!(buf.is_empty(), "framed codec must clear poisoned input");
    assert!(
        codec.is_poisoned(),
        "framed codec should poison after bomb rejection"
    );
}

fn assert_message_too_large(error: GrpcError, context: &str) {
    assert!(
        matches!(&error, GrpcError::MessageTooLarge),
        "{context} must reject as MessageTooLarge, got {error:?}"
    );
    assert_eq!(
        error.to_string(),
        "message too large",
        "{context} MessageTooLarge display changed"
    );
    let status = error.into_status();
    assert_eq!(
        status.code(),
        Code::ResourceExhausted,
        "{context} MessageTooLarge status code changed"
    );
    assert_eq!(
        status.message(),
        "message too large",
        "{context} MessageTooLarge status message changed"
    );
}
