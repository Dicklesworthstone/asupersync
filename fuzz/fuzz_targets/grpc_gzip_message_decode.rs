//! Fuzz target for gzip-compressed gRPC message decoding.
//!
//! Exercises `src/grpc/codec.rs` gzip frame handling through both direct gzip
//! decompression and framed gRPC decode paths. Coverage focuses on:
//! - valid gzip-compressed round trips
//! - malformed gzip rejection
//! - decompression-bomb guard enforcement
//! - gRPC frame truncation and declared-length mismatches

#![no_main]

use arbitrary::Arbitrary;
use asupersync::bytes::{BufMut, Bytes, BytesMut};
use asupersync::grpc::codec::{
    FramedCodec, IdentityCodec, MESSAGE_HEADER_SIZE, gzip_frame_compress, gzip_frame_decompress,
};
use asupersync::grpc::status::GrpcError;
use libfuzzer_sys::fuzz_target;

const MAX_PAYLOAD_BYTES: usize = 32 * 1024;
const MAX_GZIP_BYTES: usize = 32 * 1024;
const MAX_SUFFIX_BYTES: usize = 512;
const MAX_BOMB_BYTES: usize = 32 * 1024;

#[derive(Arbitrary, Debug, Clone)]
enum Scenario {
    RoundTrip,
    MutatedFrame,
    RawGzip,
    BombGuard,
}

#[derive(Arbitrary, Debug, Clone)]
struct FuzzInput {
    scenario: Scenario,
    payload: Vec<u8>,
    raw_gzip: Vec<u8>,
    suffix: Vec<u8>,
    decode_limit: u16,
    repeat_count: u16,
    repeat_byte: u8,
    truncate: u8,
    declared_delta: i16,
}

fuzz_target!(|input: FuzzInput| {
    fuzz_grpc_gzip_message_decode(&input);
});

fn fuzz_grpc_gzip_message_decode(input: &FuzzInput) {
    match input.scenario {
        Scenario::RoundTrip => fuzz_round_trip(input),
        Scenario::MutatedFrame => fuzz_mutated_frame(input),
        Scenario::RawGzip => fuzz_raw_gzip(input),
        Scenario::BombGuard => fuzz_bomb_guard(input),
    }
}

fn fuzz_round_trip(input: &FuzzInput) {
    let payload = bounded_bytes(&input.payload, MAX_PAYLOAD_BYTES);
    let decode_limit = decode_limit(input.decode_limit);
    let encode_limit = payload.len().saturating_add(256);
    let mut codec =
        FramedCodec::with_message_size_limits(IdentityCodec, encode_limit, decode_limit)
            .with_gzip_frame_codec();
    let mut encoded = BytesMut::new();
    let encode_result = codec.encode_message(&Bytes::copy_from_slice(payload), &mut encoded);

    match encode_result {
        Ok(()) => {
            let decode_result = codec.decode_message(&mut encoded);
            if payload.len() > decode_limit {
                assert!(matches!(decode_result, Err(GrpcError::MessageTooLarge)));
            } else {
                match decode_result {
                    Ok(Some(decoded)) => {
                        assert_eq!(decoded.as_ref(), payload);
                        assert!(encoded.is_empty());
                    }
                    Ok(None) => panic!("encoded frame must decode immediately"),
                    Err(err) => panic!("unexpected roundtrip decode error: {err:?}"),
                }
            }
        }
        Err(GrpcError::MessageTooLarge | GrpcError::Compression(_)) => {}
        Err(err) => panic!("unexpected roundtrip encode error: {err:?}"),
    }
}

fn fuzz_mutated_frame(input: &FuzzInput) {
    let payload = bounded_bytes(&input.payload, MAX_PAYLOAD_BYTES);
    let decode_limit = decode_limit(input.decode_limit);
    let encode_limit = payload.len().saturating_add(256);
    let mut body = if input.raw_gzip.first().is_some_and(|byte| byte & 1 == 0) {
        bounded_bytes(&input.raw_gzip, MAX_GZIP_BYTES).to_vec()
    } else {
        match gzip_frame_compress(payload) {
            Ok(bytes) => bytes.to_vec(),
            Err(GrpcError::Compression(_) | GrpcError::MessageTooLarge) => return,
            Err(err) => panic!("unexpected gzip encode error: {err:?}"),
        }
    };

    for (slot, byte) in body
        .iter_mut()
        .zip(bounded_bytes(&input.suffix, MAX_SUFFIX_BYTES).iter().copied())
    {
        *slot ^= byte;
    }

    body.extend_from_slice(bounded_bytes(&input.suffix, MAX_SUFFIX_BYTES));

    let truncate = usize::from(input.truncate).min(body.len());
    body.truncate(body.len().saturating_sub(truncate));

    let declared_delta = i64::from(input.declared_delta).clamp(-32, 32);
    let declared_len_base = i64::try_from(body.len()).unwrap_or(i64::from(u32::MAX));
    let declared_len_i64 =
        (declared_len_base + declared_delta).clamp(0, i64::from(u32::MAX));
    let declared_len = u32::try_from(declared_len_i64).unwrap_or(u32::MAX);

    let mut frame = BytesMut::with_capacity(MESSAGE_HEADER_SIZE + body.len());
    frame.put_u8(1);
    frame.put_u32(declared_len);
    frame.extend_from_slice(&body);

    let mut codec =
        FramedCodec::with_message_size_limits(IdentityCodec, encode_limit, decode_limit)
            .with_gzip_frame_codec();

    match codec.decode_message(&mut frame) {
        Ok(Some(decoded)) => assert!(decoded.len() <= decode_limit),
        Ok(None) => {}
        Err(
            GrpcError::Compression(_)
            | GrpcError::MessageTooLarge
            | GrpcError::Protocol(_)
            | GrpcError::InvalidMessage(_)
            | GrpcError::Transport(_)
            | GrpcError::Status(_),
        ) => {}
    }
}

fn fuzz_raw_gzip(input: &FuzzInput) {
    let raw_gzip = bounded_bytes(&input.raw_gzip, MAX_GZIP_BYTES);
    let decode_limit = decode_limit(input.decode_limit);

    match gzip_frame_decompress(raw_gzip, decode_limit) {
        Ok(decoded) => assert!(decoded.len() <= decode_limit),
        Err(GrpcError::Compression(_) | GrpcError::MessageTooLarge) => {}
        Err(err) => panic!("unexpected raw gzip decode error: {err:?}"),
    }
}

fn fuzz_bomb_guard(input: &FuzzInput) {
    let repeated_len = usize::from(input.repeat_count).min(MAX_BOMB_BYTES);
    let repeated = vec![input.repeat_byte; repeated_len];
    let decode_limit = decode_limit(input.decode_limit);
    let compressed = match gzip_frame_compress(&repeated) {
        Ok(bytes) => bytes,
        Err(GrpcError::Compression(_) | GrpcError::MessageTooLarge) => return,
        Err(err) => panic!("unexpected bomb encode error: {err:?}"),
    };

    match gzip_frame_decompress(compressed.as_ref(), decode_limit) {
        Ok(decoded) => {
            assert!(repeated_len <= decode_limit);
            assert_eq!(decoded.as_ref(), repeated.as_slice());
        }
        Err(GrpcError::MessageTooLarge) => assert!(repeated_len > decode_limit),
        Err(GrpcError::Compression(message)) => panic!("unexpected bomb decode error: {message}"),
        Err(err) => panic!("unexpected bomb decode error: {err:?}"),
    }
}

fn bounded_bytes(bytes: &[u8], max_len: usize) -> &[u8] {
    &bytes[..bytes.len().min(max_len)]
}

fn decode_limit(raw_limit: u16) -> usize {
    usize::from(raw_limit).saturating_mul(8).saturating_add(1)
}
