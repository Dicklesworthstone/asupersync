//! Structure-aware fuzz target for gRPC length-prefixed framing.
//!
//! Exercises `src/grpc/codec.rs` directly with structured message sequences
//! and malformed frame variants. The key invariants are:
//! - valid frames roundtrip through `GrpcCodec` without reordering
//! - partial frames remain pending until the declared payload is complete
//! - in-limit invalid compression-flag frames are consumed and rejected
//! - over-limit invalid compression-flag frames fail closed before consumption
//! - incomplete invalid compression-flag frames remain buffered
//! - declared lengths above the configured decode limit fail closed

#![no_main]

use arbitrary::Arbitrary;
use asupersync::bytes::{BufMut, Bytes, BytesMut};
use asupersync::codec::{Decoder, Encoder};
use asupersync::grpc::codec::MESSAGE_HEADER_SIZE;
use asupersync::grpc::{Code, GrpcCodec, GrpcError, GrpcMessage};
use libfuzzer_sys::fuzz_target;
use std::sync::OnceLock;

const MAX_INPUT_LEN: usize = 4096;
const MAX_MESSAGES: usize = 24;
const MAX_PAYLOAD_LEN: usize = 1024;
const MAX_CODEC_LIMIT: usize = 2048;

static FIXED_CANARIES: OnceLock<()> = OnceLock::new();

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
    InvalidCompressionFlag {
        flag: u8,
        payload: Vec<u8>,
    },
    OversizedLength {
        compressed: bool,
        excess: u16,
    },
    TruncatedPayload {
        compressed: bool,
        declared_extra: u8,
        actual: Vec<u8>,
    },
}

fuzz_target!(|data: &[u8]| {
    FIXED_CANARIES.get_or_init(assert_fixed_decode_canaries);

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
            expect_message_too_large(result);
            continue;
        }

        result.expect("payload within encode limit should frame successfully");
        if payload.len() > decode_limit {
            let mut oversized_decode_buf = frame.clone();
            let mut rejecting_decoder =
                GrpcCodec::with_message_size_limits(encode_limit, decode_limit);
            let decode_result =
                observe_framing_decode(&mut rejecting_decoder, &mut oversized_decode_buf);
            expect_message_too_large(decode_result);
            continue;
        }

        stream.extend_from_slice(&frame);
        encoded_frames.push(frame.freeze());
        expected.push(message);
    }

    let mut decoder = GrpcCodec::with_message_size_limits(encode_limit, decode_limit);
    let mut decode_buf = stream.clone();
    for expected_message in &expected {
        let decoded = observe_framing_decode(&mut decoder, &mut decode_buf)
            .expect("encoded stream should decode")
            .expect("encoded frame should be available");
        assert_eq!(decoded.compressed, expected_message.compressed);
        assert_eq!(decoded.data, expected_message.data);
    }
    assert!(
        observe_framing_decode(&mut decoder, &mut decode_buf)
            .unwrap()
            .is_none()
    );
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
            observe_framing_decode(&mut partial_decoder, &mut partial)
                .unwrap()
                .is_none(),
            "incomplete frame must stay pending"
        );
        assert_eq!(
            partial.len(),
            partial_len_before,
            "pending decode must not consume partial bytes"
        );

        partial.extend_from_slice(&frame[split..]);
        let decoded = observe_framing_decode(&mut partial_decoder, &mut partial)
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
            let invalid_flag = if *flag <= 1 {
                flag.saturating_add(2)
            } else {
                *flag
            };
            let payload = truncate_bytes(payload);
            encode_frame(invalid_flag, payload.len(), &payload, &mut buf);
            let frame_len = buf.len();

            let result = observe_framing_decode(&mut codec, &mut buf);
            if payload.len() > decode_limit {
                expect_message_too_large(result);
                assert_eq!(
                    buf.len(),
                    frame_len,
                    "over-limit invalid compression flag should remain buffered"
                );
            } else {
                expect_invalid_compression_flag(result, invalid_flag);
                assert_eq!(
                    buf.len(),
                    0,
                    "complete in-limit invalid compression flag should consume its frame"
                );
            }
        }
        MalformedFrame::OversizedLength { compressed, excess } => {
            let declared_len = decode_limit.saturating_add(usize::from(*excess).max(1));
            let capped_len = declared_len.min(u32::MAX as usize) as u32;
            buf.put_u8(u8::from(*compressed));
            buf.put_u32(capped_len);

            let result = observe_framing_decode(&mut codec, &mut buf);
            expect_message_too_large(result);
        }
        MalformedFrame::TruncatedPayload {
            compressed,
            declared_extra,
            actual,
        } => {
            let actual = truncate_bytes(actual);
            let declared_len = actual
                .len()
                .saturating_add(usize::from(*declared_extra).max(1));
            if declared_len > decode_limit {
                return;
            }

            encode_frame(u8::from(*compressed), declared_len, &actual, &mut buf);
            let before_len = buf.len();

            let result = observe_framing_decode(&mut codec, &mut buf);
            assert!(matches!(result, Ok(None)));
            assert_eq!(
                buf.len(),
                before_len,
                "incomplete frame must not consume buffered bytes"
            );
        }
    }
}

fn observe_framing_decode(
    codec: &mut GrpcCodec,
    buf: &mut BytesMut,
) -> Result<Option<GrpcMessage>, GrpcError> {
    let before_len = buf.len();
    let result = codec.decode(buf);
    assert!(
        buf.len() <= before_len,
        "GrpcCodec::decode grew the source buffer"
    );

    match &result {
        Ok(Some(message)) => {
            let consumed = before_len - buf.len();
            assert_eq!(
                consumed,
                MESSAGE_HEADER_SIZE + message.data.len(),
                "decoded frame consumed {consumed} bytes for payload length {}",
                message.data.len()
            );
        }
        Ok(None) => {
            assert_eq!(
                buf.len(),
                before_len,
                "incomplete frame should remain buffered"
            );
        }
        Err(GrpcError::MessageTooLarge) => {
            assert_eq!(
                buf.len(),
                before_len,
                "oversized frame should be rejected before consuming bytes"
            );
        }
        Err(GrpcError::Protocol(message)) => {
            assert!(
                !message.is_empty(),
                "protocol errors should explain the invalid frame"
            );
        }
        Err(error) => {
            assert!(
                !error.to_string().is_empty(),
                "decode error should have a non-empty description: {error:?}"
            );
        }
    }

    result
}

fn assert_fixed_decode_canaries() {
    let mut complete_invalid = BytesMut::new();
    encode_frame(2, 2, b"no", &mut complete_invalid);
    let mut codec = GrpcCodec::new();
    expect_invalid_compression_flag(observe_framing_decode(&mut codec, &mut complete_invalid), 2);
    assert!(
        complete_invalid.is_empty(),
        "complete invalid-flag frames should be consumed"
    );

    let mut oversized_invalid = BytesMut::new();
    encode_frame(2, 3, b"bad", &mut oversized_invalid);
    let mut codec = GrpcCodec::with_max_size(2);
    expect_message_too_large(observe_framing_decode(&mut codec, &mut oversized_invalid));
    assert_eq!(oversized_invalid.as_ref(), b"\x02\0\0\0\x03bad");

    let mut incomplete_invalid_header = BytesMut::from(&[2, 0, 0][..]);
    let mut codec = GrpcCodec::new();
    assert!(matches!(
        observe_framing_decode(&mut codec, &mut incomplete_invalid_header),
        Ok(None)
    ));
    assert_eq!(incomplete_invalid_header.as_ref(), &[2, 0, 0]);

    let mut incomplete_invalid_payload = BytesMut::new();
    encode_frame(2, 3, b"no", &mut incomplete_invalid_payload);
    let mut codec = GrpcCodec::new();
    assert!(matches!(
        observe_framing_decode(&mut codec, &mut incomplete_invalid_payload),
        Ok(None)
    ));
    assert_eq!(incomplete_invalid_payload.as_ref(), b"\x02\0\0\0\x03no");

    let mut oversized = BytesMut::new();
    oversized.put_u8(0);
    oversized.put_u32(3);
    let mut codec = GrpcCodec::with_max_size(2);
    expect_message_too_large(observe_framing_decode(&mut codec, &mut oversized));
    assert_eq!(oversized.as_ref(), b"\0\0\0\0\x03");
}

fn expect_message_too_large<T>(result: Result<T, GrpcError>) {
    let Err(error) = result else {
        panic!("expected MessageTooLarge error");
    };
    assert!(
        matches!(&error, GrpcError::MessageTooLarge),
        "expected MessageTooLarge error, got {error:?}"
    );
    assert_eq!(
        error.to_string(),
        "message too large",
        "MessageTooLarge display changed"
    );
    let status = error.into_status();
    assert_eq!(status.code(), Code::ResourceExhausted);
    assert_eq!(
        status.message(),
        "message too large",
        "MessageTooLarge status message changed"
    );
}

fn expect_invalid_compression_flag(
    result: Result<Option<GrpcMessage>, GrpcError>,
    invalid_flag: u8,
) {
    let Err(error) = result else {
        panic!("expected invalid compression flag Protocol error");
    };
    let expected_protocol_message = format!("invalid gRPC compression flag: {invalid_flag}");
    let expected_display = format!("protocol error: {expected_protocol_message}");

    match &error {
        GrpcError::Protocol(message) => {
            assert_eq!(
                message, &expected_protocol_message,
                "invalid compression flag protocol message changed"
            );
        }
        error => {
            panic!("expected invalid compression flag Protocol error, got {error:?}");
        }
    }
    assert_eq!(
        error.to_string(),
        expected_display,
        "invalid compression flag display changed"
    );
    let status = error.into_status();
    assert_eq!(status.code(), Code::Internal);
    assert_eq!(
        status.message(),
        expected_display,
        "invalid compression flag status message changed"
    );
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
