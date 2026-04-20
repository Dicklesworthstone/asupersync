//! Structure-aware fuzz target for direct `ProstCodec::decode` coverage.
//!
//! This target focuses on `src/grpc/protobuf.rs` rather than the outer gRPC
//! framing layer. It builds raw protobuf wire bytes from structured field
//! descriptions, then exercises decode behavior across valid messages,
//! malformed wire fragments, unknown fields, and size-limit transitions.

#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use asupersync::bytes::Bytes;
use asupersync::grpc::Codec;
use asupersync::grpc::protobuf::{ProstCodec, ProtobufError};
use libfuzzer_sys::fuzz_target;

const MAX_INPUT_LEN: usize = 4096;
const MAX_FIELDS: usize = 24;
const MAX_STRING_LEN: usize = 256;
const MAX_BYTES_LEN: usize = 512;

#[derive(Clone, PartialEq, prost::Message)]
struct InnerMessage {
    #[prost(string, tag = "1")]
    name: String,
    #[prost(int32, tag = "2")]
    value: i32,
}

#[derive(Clone, PartialEq, prost::Message)]
struct FuzzMessage {
    #[prost(string, tag = "1")]
    title: String,
    #[prost(int32, tag = "2")]
    count: i32,
    #[prost(bytes = "vec", tag = "3")]
    payload: Vec<u8>,
    #[prost(message, optional, tag = "4")]
    nested: Option<InnerMessage>,
    #[prost(string, repeated, tag = "5")]
    labels: Vec<String>,
}

#[derive(Arbitrary, Debug, Clone)]
struct CodecConfig {
    max_size_hint: u16,
    decode_mode: DecodeMode,
}

#[derive(Arbitrary, Debug, Clone, Copy)]
enum DecodeMode {
    FuzzMessage,
    InnerMessage,
}

#[derive(Arbitrary, Debug, Clone)]
struct StructuredInput {
    config: CodecConfig,
    fields: Vec<FieldSpec>,
    trailing: Vec<u8>,
}

#[derive(Arbitrary, Debug, Clone)]
enum FieldSpec {
    Title(String),
    Count(i32),
    Payload(Vec<u8>),
    Nested {
        name: String,
        value: i32,
    },
    Label(String),
    UnknownVarint {
        tag: u16,
        value: u64,
    },
    UnknownLengthDelimited {
        tag: u16,
        bytes: Vec<u8>,
    },
    MalformedLengthDelimited {
        tag: u16,
        declared_len: u16,
        actual: Vec<u8>,
    },
    InvalidWireType {
        tag: u16,
        wire_type: u8,
        bytes: Vec<u8>,
    },
    MalformedTag {
        prefix: Vec<u8>,
        suffix: Vec<u8>,
    },
}

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_INPUT_LEN {
        return;
    }

    if let Ok(input) = Unstructured::new(data).arbitrary::<StructuredInput>() {
        exercise_structured(&input);
    }

    exercise_raw(data);
});

fn exercise_structured(input: &StructuredInput) {
    let mut wire = Vec::new();
    let mut expected = FuzzMessage::default();
    let mut well_formed = true;

    for field in input.fields.iter().take(MAX_FIELDS) {
        match field {
            FieldSpec::Title(title) => {
                let title = truncate_string(title);
                encode_key(1, 2, &mut wire);
                encode_length_delimited(title.as_bytes(), &mut wire);
                expected.title = title;
            }
            FieldSpec::Count(count) => {
                encode_key(2, 0, &mut wire);
                encode_signed_int32(*count, &mut wire);
                expected.count = *count;
            }
            FieldSpec::Payload(payload) => {
                let payload = truncate_bytes(payload, MAX_BYTES_LEN);
                encode_key(3, 2, &mut wire);
                encode_length_delimited(&payload, &mut wire);
                expected.payload = payload;
            }
            FieldSpec::Nested { name, value } => {
                let nested = InnerMessage {
                    name: truncate_string(name),
                    value: *value,
                };
                let mut inner = Vec::new();
                encode_key(1, 2, &mut inner);
                encode_length_delimited(nested.name.as_bytes(), &mut inner);
                encode_key(2, 0, &mut inner);
                encode_signed_int32(nested.value, &mut inner);

                encode_key(4, 2, &mut wire);
                encode_length_delimited(&inner, &mut wire);
                expected.nested = Some(nested);
            }
            FieldSpec::Label(label) => {
                let label = truncate_string(label);
                encode_key(5, 2, &mut wire);
                encode_length_delimited(label.as_bytes(), &mut wire);
                expected.labels.push(label);
            }
            FieldSpec::UnknownVarint { tag, value } => {
                let tag = sanitize_unknown_tag(*tag);
                encode_key(tag, 0, &mut wire);
                encode_varint(*value, &mut wire);
            }
            FieldSpec::UnknownLengthDelimited { tag, bytes } => {
                let tag = sanitize_unknown_tag(*tag);
                let payload = truncate_bytes(bytes, MAX_BYTES_LEN);
                encode_key(tag, 2, &mut wire);
                encode_length_delimited(&payload, &mut wire);
            }
            FieldSpec::MalformedLengthDelimited {
                tag,
                declared_len,
                actual,
            } => {
                let tag = sanitize_unknown_tag(*tag);
                let actual = truncate_bytes(actual, MAX_BYTES_LEN);
                encode_key(tag, 2, &mut wire);
                encode_varint((*declared_len as usize + actual.len()) as u64, &mut wire);
                wire.extend_from_slice(&actual);
                well_formed = false;
            }
            FieldSpec::InvalidWireType {
                tag,
                wire_type,
                bytes,
            } => {
                let tag = sanitize_unknown_tag(*tag);
                let invalid_wire_type = 6 + (wire_type % 2);
                encode_key(tag, invalid_wire_type, &mut wire);
                wire.extend_from_slice(&truncate_bytes(bytes, 8));
                well_formed = false;
            }
            FieldSpec::MalformedTag { prefix, suffix } => {
                wire.extend_from_slice(&truncate_bytes(prefix, 12));
                wire.extend_from_slice(&truncate_bytes(suffix, 32));
                well_formed = false;
            }
        }
    }

    wire.extend_from_slice(&truncate_bytes(&input.trailing, 64));
    if !input.trailing.is_empty() {
        well_formed = false;
    }

    exercise_decode(input.config.clone(), wire, Some(expected), well_formed);
}

fn exercise_raw(data: &[u8]) {
    let configs = [
        CodecConfig {
            max_size_hint: 0,
            decode_mode: DecodeMode::FuzzMessage,
        },
        CodecConfig {
            max_size_hint: 64,
            decode_mode: DecodeMode::InnerMessage,
        },
    ];

    for config in configs {
        exercise_decode(config, data.to_vec(), None, false);
    }
}

fn exercise_decode(
    config: CodecConfig,
    wire: Vec<u8>,
    expected: Option<FuzzMessage>,
    well_formed: bool,
) {
    let bytes = Bytes::from(wire.clone());
    let max_size = compute_max_size(&wire, config.max_size_hint);

    match config.decode_mode {
        DecodeMode::FuzzMessage => {
            let mut codec = ProstCodec::<FuzzMessage, FuzzMessage>::with_max_size(max_size);
            let result = codec.decode(&bytes);
            assert_decode_contract(&result, bytes.len(), max_size);

            if well_formed && bytes.len() <= max_size {
                if let (Ok(decoded), Some(expected)) = (result.as_ref(), expected.as_ref()) {
                    assert_eq!(decoded, expected, "well-formed structured decode drifted");

                    let mut reencode =
                        ProstCodec::<FuzzMessage, FuzzMessage>::with_max_size(max_size);
                    let encoded = reencode
                        .encode(decoded)
                        .expect("decoded message should re-encode");
                    let decoded_again = reencode
                        .decode(&encoded)
                        .expect("re-encoded message should decode");
                    assert_eq!(
                        &decoded_again, decoded,
                        "decode/re-encode/decode should be stable"
                    );
                }
            }
        }
        DecodeMode::InnerMessage => {
            let mut codec = ProstCodec::<InnerMessage, InnerMessage>::with_max_size(max_size);
            let result = codec.decode(&bytes);
            assert_decode_contract(&result, bytes.len(), max_size);

            if well_formed && bytes.is_empty() {
                let decoded = result.expect("empty bytes should decode as default message");
                assert_eq!(decoded, InnerMessage::default());
            }
        }
    }
}

fn assert_decode_contract<T>(result: &Result<T, ProtobufError>, byte_len: usize, max_size: usize) {
    match result {
        Ok(_) => {
            assert!(
                byte_len <= max_size,
                "decode succeeded past configured max size: len={byte_len}, max={max_size}"
            );
        }
        Err(ProtobufError::MessageTooLarge { size, limit }) => {
            assert_eq!(*size, byte_len, "reported oversize must match input length");
            assert_eq!(
                *limit, max_size,
                "reported oversize limit must match codec config"
            );
            assert!(
                byte_len > max_size,
                "MessageTooLarge requires input to exceed configured limit"
            );
        }
        Err(ProtobufError::DecodeError(_)) => {
            assert!(
                byte_len <= max_size,
                "oversize decode must fail as MessageTooLarge before wire decode"
            );
        }
        Err(ProtobufError::EncodeError(_)) => {
            panic!("decode path must not surface encode errors");
        }
    }
}

fn compute_max_size(wire: &[u8], hint: u16) -> usize {
    if wire.is_empty() {
        return 0;
    }

    let bias = (hint as usize) % 96;
    let len = wire.len();
    match hint % 4 {
        0 => len.saturating_sub(bias.min(len)),
        1 => len,
        2 => len.saturating_add(bias),
        _ => bias,
    }
}

fn sanitize_unknown_tag(tag: u16) -> u32 {
    let tag = u32::from(tag.max(6));
    tag.min(2048)
}

fn truncate_string(value: &str) -> String {
    value.chars().take(MAX_STRING_LEN).collect()
}

fn truncate_bytes(value: &[u8], max_len: usize) -> Vec<u8> {
    value.iter().copied().take(max_len).collect()
}

fn encode_key(tag: u32, wire_type: u8, out: &mut Vec<u8>) {
    encode_varint(((tag << 3) | u32::from(wire_type)) as u64, out);
}

fn encode_length_delimited(bytes: &[u8], out: &mut Vec<u8>) {
    encode_varint(bytes.len() as u64, out);
    out.extend_from_slice(bytes);
}

fn encode_signed_int32(value: i32, out: &mut Vec<u8>) {
    encode_varint(value as i64 as u64, out);
}

fn encode_varint(mut value: u64, out: &mut Vec<u8>) {
    while value >= 0x80 {
        out.push((value as u8 & 0x7f) | 0x80);
        value >>= 7;
    }
    out.push(value as u8);
}
