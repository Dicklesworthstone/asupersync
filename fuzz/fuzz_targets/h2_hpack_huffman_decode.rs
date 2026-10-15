#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

use asupersync::bytes::{Bytes, BytesMut};
use asupersync::http::h2::error::ErrorCode;
use asupersync::http::h2::{H2Error, HpackDecoder};

const MAX_HUFFMAN_BYTES: usize = 8 * 1024;
const STATIC_NAME_INDEX: usize = 16; // accept-encoding
const STRING_LENGTH_EXCEEDS_BUFFER: &str = "string length exceeds buffer";

#[derive(Arbitrary, Debug)]
struct HuffmanDecodeInput {
    bytes: Vec<u8>,
    mode: DecodeMode,
    declared_len_extra: u8,
}

#[derive(Arbitrary, Debug, Clone, Copy)]
enum DecodeMode {
    ExactLength,
    DeclaredLengthTooLong,
    TruncatedLengthInteger,
    ExtraHeaderBlockBytes,
}

fuzz_target!(|input: HuffmanDecodeInput| {
    assert_known_truncated_eos_prefix_errors();

    let huffman_bytes = bounded(&input.bytes);
    let declared_len = match input.mode {
        DecodeMode::ExactLength
        | DecodeMode::TruncatedLengthInteger
        | DecodeMode::ExtraHeaderBlockBytes => huffman_bytes.len(),
        DecodeMode::DeclaredLengthTooLong => huffman_bytes
            .len()
            .saturating_add(usize::from(input.declared_len_extra % 8) + 1),
    };

    let mut block = match input.mode {
        DecodeMode::TruncatedLengthInteger => truncated_length_integer_block(),
        _ => literal_huffman_value_block(huffman_bytes, declared_len),
    };

    if matches!(input.mode, DecodeMode::ExtraHeaderBlockBytes) {
        block.extend_from_slice(&input.bytes[input.bytes.len().saturating_sub(4)..]);
    }

    let result = decode_header_block(&block);

    if matches!(input.mode, DecodeMode::DeclaredLengthTooLong) {
        assert_length_error(result);
    }
});

fn bounded(bytes: &[u8]) -> &[u8] {
    &bytes[..bytes.len().min(MAX_HUFFMAN_BYTES)]
}

fn literal_huffman_value_block(huffman_bytes: &[u8], declared_len: usize) -> BytesMut {
    let mut block = BytesMut::new();
    encode_integer(&mut block, STATIC_NAME_INDEX, 4, 0x00);
    encode_integer(&mut block, declared_len, 7, 0x80);
    block.extend_from_slice(huffman_bytes);
    block
}

fn truncated_length_integer_block() -> BytesMut {
    let mut block = BytesMut::new();
    encode_integer(&mut block, STATIC_NAME_INDEX, 4, 0x00);
    block.extend_from_slice(&[0xff, 0x80, 0x80]);
    block
}

fn decode_header_block(block: &[u8]) -> Result<(), H2Error> {
    let mut decoder = HpackDecoder::new();
    let mut src = Bytes::copy_from_slice(block);
    decoder.decode(&mut src).map(|_| ())
}

fn assert_known_truncated_eos_prefix_errors() {
    for eos_prefix in [b"".as_slice(), &[0xff], &[0xff, 0xff], &[0xff, 0xff, 0xff]] {
        let block = literal_huffman_value_block(eos_prefix, eos_prefix.len() + 1);
        assert_length_error(decode_header_block(&block));
    }
}

fn assert_length_error(result: Result<(), H2Error>) {
    let err = result.expect_err("truncated Huffman byte sequence must be rejected");
    assert_eq!(err.code, ErrorCode::CompressionError);
    assert_eq!(err.message, STRING_LENGTH_EXCEEDS_BUFFER);
    assert!(
        err.is_connection_error(),
        "HPACK string length errors should be connection-level: {err:?}"
    );
    assert_eq!(
        err.to_string(),
        format!("HTTP/2 connection error (COMPRESSION_ERROR): {STRING_LENGTH_EXCEEDS_BUFFER}")
    );
}

fn encode_integer(dst: &mut BytesMut, value: usize, prefix_bits: u8, prefix: u8) {
    let max_first = (1usize << prefix_bits) - 1;

    if value < max_first {
        dst.extend_from_slice(&[prefix | value as u8]);
        return;
    }

    dst.extend_from_slice(&[prefix | max_first as u8]);
    let mut remaining = value - max_first;
    while remaining >= 128 {
        dst.extend_from_slice(&[((remaining & 0x7f) as u8) | 0x80]);
        remaining >>= 7;
    }
    dst.extend_from_slice(&[remaining as u8]);
}
