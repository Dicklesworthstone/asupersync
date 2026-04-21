//! Structure-aware fuzz target for gRPC length-prefixed framing.
//!
//! Exercises `src/grpc/codec.rs` directly with structured message sequences
//! and malformed frame variants. The key invariants are:
//! - valid frames roundtrip through `GrpcCodec` without reordering
//! - partial frames remain pending until the declared payload is complete
//! - invalid compression flags reject without consuming the buffer
//! - declared lengths above the configured decode limit fail closed

#![no_main]

use arbitrary::Arbitrary;
use asupersync::bytes::{BufMut, Bytes, BytesMut};
use asupersync::codec::{Decoder, Encoder};
use asupersync::grpc::codec::MESSAGE_HEADER_SIZE;
use asupersync::grpc::{GrpcCodec, GrpcError, GrpcMessage};
use libfuzzer_sys::fuzz_target;

const MAX_INPUT_LEN: usize = 4096;
const MAX_MESSAGES: usize = 24;
const MAX_PAYLOAD_LEN: usize = 1024;
const MAX_CODEC_LIMIT: usize = 2048;

#[derive(Arbitrary, Debug, Clone)]
struct FuzzInput {
    config: CodecConfig,
    messages: Vec<MessageSpec>,
    malformed: Option<MalformedFrame>,
}

#[derive(Arbitrary, Debug, Clone, Copy)]
struct CodecConfig {
    encode_limit: u16,
    decode_limit: u16,
    split_at: u16,
}

#[derive(Arbitrary, Debug, Clone)]
struct MessageSpec {
    compressed: bool,
    payload: Vec<u8>,
}

#[derive(Arbitrary, Debug, Clone)]
enum MalformedFrame {
    InvalidCompressionFlag { flag: u8, payload: Vec<u8> },
    OversizedLength { compressed: bool, excess: u16 },
    TruncatedPayload {
        compressed: bool,
        declared_extra: u8,
        actual: Vec<u8>,
    },
}

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_INPUT_LEN {
        return;
    }

    if let Ok(input) = arbitrary::Unstructured::new(data).arbitrary::<FuzzInput>() {
        exercise(&input);
    }
});

fn exercise(input: &FuzzInput) {
    let encode_limit = normalize_limit(input.config.encode_limit);
    let decode_limit = normalize_limit(input.config.decode_limit);

    exercise_roundtrip_and_partial(input, encode_limit, decode_limit);

    if let Some(malformed) = &input.malformed {
        exercise_malformed(malformed, decode_limit);
    }
}

fn exercise_roundtrip_and_partial(input: &FuzzInput, encode_limit: usize, decode_limit: usize) {
    let mut encoder = GrpcCodec::with_message_size_limits(encode_limit, decode_limit);
    let mut stream = BytesMut::new();
    let mut encoded_frames = Vec::new();
    let mut expected = Vec::new();

    for spec in input.messages.iter().take(MAX_MESSAGES) {
        let payload = truncate_bytes(&spec.payload);
        let message = if spec.compressed {
            GrpcMessage::compressed(Bytes::from(payload.clone()))
        } else {
            GrpcMessage::new(Bytes::from(payload.clone()))
        };

        let mut frame = BytesMut::new();
        let result = encoder.encode(message.clone(), &mut frame);

        if payload.len() > encode_limit {
            assert!(
                matches!(result, Err(GrpcError::MessageTooLarge)),
                "payload larger than encode limit must fail closed"
            );
            continue;
        }

        result.expect("payload within encode limit should frame successfully");
        if payload.len() > decode_limit {
            let mut oversized_decode_buf = frame.clone();
            let mut rejecting_decoder =
                GrpcCodec::with_message_size_limits(encode_limit, decode_limit);
            let decode_result = rejecting_decoder.decode(&mut oversized_decode_buf);
            assert!(
                matches!(decode_result, Err(GrpcError::MessageTooLarge)),
                "payload larger than decode limit must fail closed"
            );
            continue;
        }

        stream.extend_from_slice(&frame);
        encoded_frames.push(frame.freeze());
        expected.push(message);
    }

    let mut decoder = GrpcCodec::with_message_size_limits(encode_limit, decode_limit);
    let mut decode_buf = stream.clone();
    for expected_message in &expected {
        let decoded = decoder
            .decode(&mut decode_buf)
            .expect("encoded stream should decode")
            .expect("encoded frame should be available");
        assert_eq!(decoded.compressed, expected_message.compressed);
        assert_eq!(decoded.data, expected_message.data);
    }
    assert!(decoder.decode(&mut decode_buf).unwrap().is_none());
    assert!(decode_buf.is_empty(), "decoder should drain encoded stream");

    if let (Some(frame), Some(expected_message)) = (encoded_frames.first(), expected.first()) {
        let split = usize::min(
            usize::from(input.config.split_at),
            frame.len().saturating_sub(1),
        );
        let mut partial = BytesMut::from(&frame[..split]);
        let partial_len_before = partial.len();
        let mut partial_decoder = GrpcCodec::with_message_size_limits(encode_limit, decode_limit);
        assert!(
            partial_decoder.decode(&mut partial).unwrap().is_none(),
            "incomplete frame must stay pending"
        );
        assert_eq!(
            partial.len(),
            partial_len_before,
            "pending decode must not consume partial bytes"
        );

        partial.extend_from_slice(&frame[split..]);
        let decoded = partial_decoder
            .decode(&mut partial)
            .expect("completed partial frame should decode")
            .expect("completed partial frame should be available");
        assert_eq!(decoded.compressed, expected_message.compressed);
        assert_eq!(decoded.data, expected_message.data);
        assert!(partial.is_empty(), "completed frame should drain buffer");
    }
}

fn exercise_malformed(frame: &MalformedFrame, decode_limit: usize) {
    let mut codec = GrpcCodec::with_message_size_limits(MAX_CODEC_LIMIT, decode_limit);
    let mut buf = BytesMut::new();

    match frame {
        MalformedFrame::InvalidCompressionFlag { flag, payload } => {
            let invalid_flag = if *flag <= 1 { flag.saturating_add(2) } else { *flag };
            let payload = truncate_bytes(payload);
            encode_frame(invalid_flag, payload.len(), &payload, &mut buf);
            let before = buf.clone();

            let result = codec.decode(&mut buf);
            assert!(matches!(result, Err(GrpcError::Protocol(_))));
            assert_eq!(
                buf, before,
                "invalid compression flag should leave buffer untouched"
            );
        }
        MalformedFrame::OversizedLength { compressed, excess } => {
            let declared_len = decode_limit.saturating_add(usize::from(*excess).max(1));
            let capped_len = declared_len.min(u32::MAX as usize) as u32;
            buf.put_u8(u8::from(*compressed));
            buf.put_u32(capped_len);

            let result = codec.decode(&mut buf);
            assert!(matches!(result, Err(GrpcError::MessageTooLarge)));
        }
        MalformedFrame::TruncatedPayload {
            compressed,
            declared_extra,
            actual,
        } => {
            let actual = truncate_bytes(actual);
            let declared_len = actual.len().saturating_add(usize::from(*declared_extra).max(1));
            if declared_len > decode_limit {
                return;
            }

            encode_frame(u8::from(*compressed), declared_len, &actual, &mut buf);
            let before_len = buf.len();

            let result = codec.decode(&mut buf);
            assert!(matches!(result, Ok(None)));
            assert_eq!(
                buf.len(),
                before_len,
                "incomplete frame must not consume buffered bytes"
            );
        }
    }
}

fn encode_frame(flag: u8, declared_len: usize, payload: &[u8], dst: &mut BytesMut) {
    dst.put_u8(flag);
    dst.put_u32(declared_len.min(u32::MAX as usize) as u32);
    dst.extend_from_slice(payload);
}

fn normalize_limit(limit: u16) -> usize {
    usize::from(limit).clamp(MESSAGE_HEADER_SIZE, MAX_CODEC_LIMIT)
}

fn truncate_bytes(bytes: &[u8]) -> Vec<u8> {
    bytes.iter().copied().take(MAX_PAYLOAD_LEN).collect()
}
