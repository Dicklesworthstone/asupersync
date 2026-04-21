//! Structure-aware fuzz target for `src/grpc/protobuf.rs`.
//!
//! This target exercises `ProstCodec` directly rather than the outer gRPC
//! length-prefixed framing layer. It focuses on:
//! - successful encode/decode roundtrips for bounded structured messages
//! - deterministic re-encoding of decoded values
//! - unknown-field tolerance on decode
//! - malformed/truncated/raw wire bytes returning errors rather than panicking
//! - size-limit enforcement on both encode and decode

#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use asupersync::bytes::Bytes;
use asupersync::grpc::Codec;
use asupersync::grpc::protobuf::{ProstCodec, ProtobufError};
use libfuzzer_sys::fuzz_target;
use prost::Message as _;

const MAX_INPUT_LEN: usize = 4096;
const MAX_STRING_LEN: usize = 128;
const MAX_BYTES_LEN: usize = 512;
const MAX_LABELS: usize = 8;
const MAX_RAW_LEN: usize = 1024;

#[derive(Clone, PartialEq, Eq, Arbitrary, prost::Message)]
struct NestedMessage {
    #[prost(string, tag = "1")]
    name: String,
    #[prost(int32, tag = "2")]
    count: i32,
}

#[derive(Clone, PartialEq, Eq, Arbitrary, prost::Message)]
struct RoundTripMessage {
    #[prost(string, tag = "1")]
    name: String,
    #[prost(bytes = "vec", tag = "2")]
    payload: Vec<u8>,
    #[prost(message, optional, tag = "3")]
    nested: Option<NestedMessage>,
    #[prost(string, repeated, tag = "4")]
    labels: Vec<String>,
    #[prost(sint64, tag = "5")]
    delta: i64,
    #[prost(uint64, tag = "6")]
    nonce: u64,
}

#[derive(Clone, Debug, Arbitrary)]
struct HarnessInput {
    limit_hint: u16,
    message: RoundTripMessage,
    raw: Vec<u8>,
    mutation: Mutation,
}

#[derive(Clone, Debug, Arbitrary)]
enum Mutation {
    None,
    AppendUnknownVarint { tag: u16, value: u64 },
    FlipByte { offset: u16, xor_mask: u8 },
    Truncate { keep: u16 },
    ReplaceWithRaw,
}

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_INPUT_LEN {
        return;
    }

    if let Ok(input) = Unstructured::new(data).arbitrary::<HarnessInput>() {
        exercise_structured(&input);
    }

    exercise_raw(data);
});

fn exercise_structured(input: &HarnessInput) {
    let message = sanitize_message(input.message.clone());
    let limit = size_limit(input.limit_hint);
    let expected_len = message.encoded_len();
    let mut codec = ProstCodec::<RoundTripMessage, RoundTripMessage>::with_max_size(limit);

    match codec.encode(&message) {
        Ok(encoded) => {
            assert!(
                expected_len <= limit,
                "encode unexpectedly succeeded past limit: len={expected_len} limit={limit}"
            );

            let decoded = codec
                .decode(&encoded)
                .expect("encoded message must decode with the same codec");
            assert_eq!(decoded, message, "roundtrip through ProstCodec changed the message");

            let reencoded = codec
                .encode(&decoded)
                .expect("decoded message must re-encode successfully");
            assert_eq!(
                encoded, reencoded,
                "re-encoding a decoded message should be deterministic"
            );

            let (mutated, expect_same_value) = mutate_bytes(&encoded, &input.raw, &input.mutation);
            exercise_decode(limit, mutated, expect_same_value.then_some(&message));
        }
        Err(ProtobufError::MessageTooLarge {
            size,
            limit: err_limit,
        }) => {
            assert_eq!(size, expected_len);
            assert_eq!(err_limit, limit);

            let raw = Bytes::from(truncate_bytes(&input.raw, MAX_RAW_LEN));
            exercise_decode(limit, raw, None);
        }
        Err(err) => panic!("unexpected encode error from ProstCodec: {err}"),
    }
}

fn exercise_raw(data: &[u8]) {
    let raw = Bytes::from(truncate_bytes(data, MAX_RAW_LEN));
    let sizes = [
        32usize,
        256usize,
        raw.len().saturating_sub(1).max(1),
        raw.len().saturating_add(8),
    ];

    for limit in sizes {
        exercise_decode(limit, raw.clone(), None);
    }
}

fn exercise_decode(
    limit: usize,
    wire: Bytes,
    expected_message: Option<&RoundTripMessage>,
) {
    let mut codec = ProstCodec::<RoundTripMessage, RoundTripMessage>::with_max_size(limit);

    match codec.decode(&wire) {
        Ok(decoded) => {
            if let Some(expected) = expected_message {
                assert_eq!(
                    &decoded, expected,
                    "unknown-field tolerant decode should preserve the original message"
                );
            }

            let reencoded = codec
                .encode(&decoded)
                .expect("successfully decoded messages must re-encode");
            let decoded_again = codec
                .decode(&reencoded)
                .expect("re-encoded messages must decode again");
            assert_eq!(decoded_again, decoded);
        }
        Err(ProtobufError::MessageTooLarge {
            size,
            limit: err_limit,
        }) => {
            assert_eq!(size, wire.len());
            assert_eq!(err_limit, limit);
        }
        Err(ProtobufError::DecodeError(_)) => {}
        Err(err) => panic!("unexpected decode error variant from ProstCodec: {err}"),
    }
}

fn mutate_bytes(encoded: &Bytes, raw: &[u8], mutation: &Mutation) -> (Bytes, bool) {
    let mut bytes = encoded.to_vec();

    match mutation {
        Mutation::None => (encoded.clone(), true),
        Mutation::AppendUnknownVarint { tag, value } => {
            append_unknown_varint(&mut bytes, *tag, *value);
            (Bytes::from(bytes), true)
        }
        Mutation::FlipByte { offset, xor_mask } => {
            if !bytes.is_empty() {
                let idx = (*offset as usize) % bytes.len();
                bytes[idx] ^= *xor_mask;
            }
            (Bytes::from(bytes), false)
        }
        Mutation::Truncate { keep } => {
            let keep = (*keep as usize).min(bytes.len());
            bytes.truncate(keep);
            (Bytes::from(bytes), false)
        }
        Mutation::ReplaceWithRaw => (Bytes::from(truncate_bytes(raw, MAX_RAW_LEN)), false),
    }
}

fn append_unknown_varint(buf: &mut Vec<u8>, tag: u16, value: u64) {
    let tag = sanitize_unknown_tag(tag);
    encode_varint((tag as u64) << 3, buf);
    encode_varint(value, buf);
}

fn encode_varint(mut value: u64, buf: &mut Vec<u8>) {
    while value >= 0x80 {
        buf.push((value as u8 & 0x7f) | 0x80);
        value >>= 7;
    }
    buf.push(value as u8);
}

fn sanitize_unknown_tag(tag: u16) -> u16 {
    let tag = tag.max(16);
    if tag == 0 { 16 } else { tag }
}

fn size_limit(hint: u16) -> usize {
    32 + (hint as usize * 32)
}

fn sanitize_message(mut message: RoundTripMessage) -> RoundTripMessage {
    message.name = truncate_string(&message.name);
    message.payload = truncate_bytes(&message.payload, MAX_BYTES_LEN);

    if let Some(nested) = &mut message.nested {
        nested.name = truncate_string(&nested.name);
    }

    message.labels.truncate(MAX_LABELS);
    for label in &mut message.labels {
        *label = truncate_string(label);
    }

    message
}

fn truncate_string(input: &str) -> String {
    input.chars().take(MAX_STRING_LEN).collect()
}

fn truncate_bytes(input: &[u8], max_len: usize) -> Vec<u8> {
    input.iter().copied().take(max_len).collect()
}
