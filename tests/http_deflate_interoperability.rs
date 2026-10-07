//! HTTP deflate interoperability and hostile-stream regressions (br-asupersync-zodgeb).
#![cfg(feature = "compression")]

use asupersync::http::compress::{
    Compressor, ContentEncoding, Decompressor, DeflateCompressor, DeflateDecompressor,
    make_compressor, negotiate_encoding,
};
use flate2::Compression;
use std::io::{Read, Write};

fn reference_encode(input: &[u8], zlib: bool) -> Vec<u8> {
    if zlib {
        let mut encoder = flate2::write::ZlibEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(input).unwrap();
        encoder.finish().unwrap()
    } else {
        let mut encoder = flate2::write::DeflateEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(input).unwrap();
        encoder.finish().unwrap()
    }
}

#[test]
fn negotiated_deflate_is_decodable_by_a_zlib_client() {
    let input = b"HTTP response payload: repeated repeated repeated.";
    let encoding = negotiate_encoding(
        Some("deflate, identity;q=0"),
        &[ContentEncoding::Gzip, ContentEncoding::Deflate, ContentEncoding::Identity],
    )
    .unwrap();
    assert_eq!(encoding, ContentEncoding::Deflate);
    let mut encoder = make_compressor(encoding).unwrap();
    let mut wire = Vec::new();
    for chunk in input.chunks(3) {
        encoder.compress(chunk, &mut wire).unwrap();
    }
    encoder.finish(&mut wire).unwrap();
    let mut decoded = Vec::new();
    flate2::read::ZlibDecoder::new(wire.as_slice())
        .read_to_end(&mut decoded)
        .unwrap();
    assert_eq!(decoded, input);
}

#[test]
fn reference_zlib_and_legacy_raw_decode_at_every_split() {
    let input = b"A reference encoder, not our own round trip, supplies this stream.";
    for zlib in [false, true] {
        let wire = reference_encode(input, zlib);
        for split in 0..=wire.len() {
            let mut decoder = DeflateDecompressor::new(Some(input.len()));
            let mut decoded = Vec::new();
            decoder.decompress(&wire[..split], &mut decoded).unwrap();
            decoder.decompress(&[], &mut decoded).unwrap();
            decoder.decompress(&wire[split..], &mut decoded).unwrap();
            decoder.finish(&mut decoded).unwrap();
            assert_eq!(decoded, input, "zlib={zlib}, split={split}");
        }
    }
}

#[test]
fn large_expansion_drains_multiple_scratch_buffers() {
    let input = vec![b'a'; 128 * 1024];
    for zlib in [false, true] {
        let wire = reference_encode(&input, zlib);
        for chunk_size in [1, 2, 5, wire.len()] {
            let mut decoder = DeflateDecompressor::new(Some(input.len()));
            let mut decoded = Vec::new();
            for chunk in wire.chunks(chunk_size) {
                decoder.decompress(chunk, &mut decoded).unwrap();
            }
            decoder.finish(&mut decoded).unwrap();
            assert_eq!(decoded, input, "zlib={zlib}, chunks={chunk_size}");
        }
    }
}

#[test]
fn corrupted_adler_checksum_is_not_retried_as_raw() {
    let mut wire = reference_encode(b"checksum protected payload", true);
    *wire.last_mut().unwrap() ^= 1;
    let mut decoder = DeflateDecompressor::new(Some(1024));
    let mut output = b"existing".to_vec();
    assert!(decoder.decompress(&wire, &mut output).is_err());
    assert_eq!(output, b"existing", "failing call must not publish partial bytes");
    assert!(decoder.decompress(&[], &mut output).unwrap_err().to_string().contains("poisoned"));
    assert!(decoder.finish(&mut output).is_err());
    assert_eq!(output, b"existing");
}

#[test]
fn every_truncated_prefix_fails_completion() {
    for zlib in [false, true] {
        let wire = reference_encode(b"all compressed framing must be present", zlib);
        for len in 0..wire.len() {
            let mut decoder = DeflateDecompressor::new(Some(1024));
            let mut output = Vec::new();
            let result = decoder
                .decompress(&wire[..len], &mut output)
                .and_then(|()| decoder.finish(&mut output));
            assert!(result.is_err(), "accepted zlib={zlib}, prefix={len}");
            let before = output.clone();
            assert!(decoder.finish(&mut output).is_err());
            assert!(decoder.decompress(&wire[len..], &mut output).is_err());
            assert_eq!(output, before);
        }
    }
}

#[test]
fn trailing_bytes_fail_in_the_same_or_a_later_chunk() {
    for zlib in [false, true] {
        let wire = reference_encode(b"one stream only", zlib);
        let mut decoder = DeflateDecompressor::new(Some(1024));
        let mut with_tail = wire.clone();
        with_tail.push(0);
        let mut output = Vec::new();
        assert!(decoder.decompress(&with_tail, &mut output).is_err());
        assert!(output.is_empty());
        assert!(decoder.finish(&mut output).is_err());

        let mut decoder = DeflateDecompressor::new(Some(1024));
        decoder.decompress(&wire, &mut output).unwrap();
        let before = output.clone();
        assert!(decoder.decompress(b"extra", &mut output).is_err());
        assert!(decoder.finish(&mut output).is_err());
        assert_eq!(output, before);
    }
}

#[test]
fn output_limit_is_cumulative_across_chunks_and_sticky_after_error() {
    let input = vec![b'z'; 64 * 1024];
    let limit = input.len() - 1;
    for zlib in [false, true] {
        let wire = reference_encode(&input, zlib);
        let mut decoder = DeflateDecompressor::new(Some(limit));
        let mut output = Vec::new();
        let mut rejected = false;
        for chunk in wire.chunks(1) {
            let before = output.len();
            if decoder.decompress(chunk, &mut output).is_err() {
                assert_eq!(output.len(), before);
                rejected = true;
                break;
            }
            assert!(output.len() <= limit);
        }
        assert!(rejected, "zlib={zlib}: output cap was not enforced");
        let before = output.clone();
        assert!(decoder.decompress(&wire, &mut output).is_err());
        assert!(decoder.finish(&mut output).is_err());
        assert_eq!(output, before);
    }
}

#[test]
fn valid_empty_streams_obey_zero_limit_and_finish_is_idempotent() {
    for zlib in [false, true] {
        let wire = reference_encode(b"", zlib);
        let mut decoder = DeflateDecompressor::new(Some(0));
        let mut output = Vec::new();
        for byte in wire.chunks(1) {
            decoder.decompress(byte, &mut output).unwrap();
        }
        decoder.finish(&mut output).unwrap();
        decoder.finish(&mut output).unwrap();
        assert!(decoder.decompress(&wire, &mut output).is_err());
        assert!(output.is_empty());
    }
}

#[test]
fn preset_dictionary_stream_fails_without_raw_fallback() {
    // RFC 1950: valid CMF/FLG with FDICT, followed by an unavailable DICTID.
    let wire = [0x78, 0x20, 0x00, 0x00, 0x00, 0x01, 0x03, 0x00];
    let mut decoder = DeflateDecompressor::new(Some(1024));
    let mut output = Vec::new();
    assert!(decoder.decompress(&wire, &mut output).is_err());
    assert!(output.is_empty());
    assert!(decoder.finish(&mut output).is_err());
}

#[test]
fn zlib_wrapper_bytes_are_included_in_compressed_output_limit() {
    let mut encoder = DeflateCompressor::with_output_limit(Some(2));
    let mut output = Vec::new();
    let result = encoder
        .compress(b"", &mut output)
        .and_then(|()| encoder.finish(&mut output));
    assert!(result.is_err(), "a header alone is not a complete HTTP deflate body");
    assert!(output.len() <= 2);
}
