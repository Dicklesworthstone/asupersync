//! gRPC-Web compressed-message decoder fuzz target.
//!
//! Fuzzes the gRPC-Web frame decoder in src/grpc/web.rs with structure-aware
//! testing of compressed data frames and trailer frames.
//!
//! # gRPC-Web Frame Format (per spec)
//! - 1 byte flag: bit 0 = compressed, bit 7 = trailer, bits 1-6 reserved (must be 0)
//! - 4 bytes length (big-endian)
//! - Variable payload:
//!   - Data frames: raw message bytes (potentially compressed)
//!   - Trailer frames: HTTP/1.1 header block (`key: value\r\n` pairs)
//!
//! # Compressed Message Focus
//! This target specifically focuses on the compression handling path:
//! - Data frames with compression flag (bit 0) set
//! - Base64-encoded streams (gRPC-Web-text mode)
//! - Trailer frame metadata parsing with binary (-bin) values
//!
//! # Edge Cases Tested
//! - Reserved flag bits (must trigger protocol error)
//! - Oversized frames (> max_frame_size)
//! - Malformed base64 in trailer binary metadata
//! - Duplicate grpc-status/grpc-message headers
//! - Invalid UTF-8 in trailer blocks
//! - Compression flag on trailer frames (unsupported)
//!
//! # Running
//! ```bash
//! cargo +nightly fuzz run grpc_web_compressed_message -- -runs=1000000
//! ```

#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use asupersync::bytes::BytesMut;
use asupersync::grpc::web::{
    Base64StreamDecoder, WebFrame, WebFrameCodec, base64_decode, decode_trailers,
};
use libfuzzer_sys::fuzz_target;

/// Maximum frame size for testing (16KB, reasonable for fuzzing)
const MAX_FUZZ_FRAME_SIZE: usize = 16 * 1024;

/// Fuzzing strategies for gRPC-Web frame generation
#[derive(Debug, Clone, Copy, Arbitrary)]
enum FuzzStrategy {
    /// Raw bytes - completely random frame data
    RawBytes,
    /// Valid frame header + random payload
    ValidFrameRandomPayload,
    /// Compressed data frame with structured payload
    CompressedDataFrame,
    /// Trailer frame with malformed headers
    TrailerFrameCorruption,
    /// Base64-encoded stream (gRPC-Web-text mode)
    Base64Stream,
}

/// Structure-aware gRPC-Web frame for fuzzing
#[derive(Debug, Clone, Arbitrary)]
struct FuzzWebFrame {
    /// Fuzzing strategy to apply
    strategy: FuzzStrategy,
    /// Flag byte (bit patterns)
    flag: u8,
    /// Frame payload
    payload: Vec<u8>,
    /// For trailer frames: HTTP-style headers
    trailer_headers: Vec<TrailerHeader>,
    /// For base64 testing: streaming chunks
    base64_chunks: Vec<Vec<u8>>,
}

/// Fuzzed trailer header for testing metadata parsing
#[derive(Debug, Clone, Arbitrary)]
struct TrailerHeader {
    key: String,
    value: String,
    /// Whether this should be treated as binary (-bin suffix)
    is_binary: bool,
}

impl FuzzWebFrame {
    /// Generate frame bytes according to the fuzzing strategy
    fn to_bytes(&self) -> Vec<u8> {
        match self.strategy {
            FuzzStrategy::RawBytes => {
                // Completely random bytes (tests parser resilience)
                self.payload.clone()
            }
            FuzzStrategy::ValidFrameRandomPayload => {
                self.build_frame_with_header(self.flag, &self.payload)
            }
            FuzzStrategy::CompressedDataFrame => {
                // Focus on compression flag (bit 0) testing
                let compressed_flag = self.flag | 0x01;
                self.build_frame_with_header(compressed_flag, &self.payload)
            }
            FuzzStrategy::TrailerFrameCorruption => {
                // Trailer frame (bit 7) with potentially malformed headers
                let trailer_flag = self.flag | 0x80;
                let headers = self.build_trailer_headers();
                self.build_frame_with_header(trailer_flag, headers.as_bytes())
            }
            FuzzStrategy::Base64Stream => {
                // Test base64 stream decoder with chunked input
                self.payload.clone() // Raw base64 data for stream testing
            }
        }
    }

    /// Build a properly framed gRPC-Web message
    fn build_frame_with_header(&self, flag: u8, payload: &[u8]) -> Vec<u8> {
        let mut frame = Vec::with_capacity(5 + payload.len());
        frame.push(flag);
        frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        frame.extend_from_slice(payload);
        frame
    }

    /// Build HTTP-style trailer headers (potentially malformed)
    fn build_trailer_headers(&self) -> String {
        let mut headers = String::new();

        // Always include grpc-status (required)
        headers.push_str("grpc-status: 0\r\n");

        for header in &self.trailer_headers {
            let key = if header.is_binary && !header.key.ends_with("-bin") {
                format!("{}-bin", header.key)
            } else {
                header.key.clone()
            };
            headers.push_str(&format!("{}: {}\r\n", key, header.value));
        }

        headers
    }
}

fuzz_target!(|data: &[u8]| {
    run_fixed_canaries();

    // Fuzz target entry point with input size guard
    if data.is_empty() || data.len() > MAX_FUZZ_FRAME_SIZE {
        return;
    }

    // Generate structured fuzz input
    let mut unstructured = Unstructured::new(data);
    let Ok(fuzz_frame) = FuzzWebFrame::arbitrary(&mut unstructured) else {
        return;
    };

    // Fuzz main WebFrameCodec::decode() path
    fuzz_frame_codec(&fuzz_frame);

    // Fuzz direct trailer decoding
    if matches!(fuzz_frame.strategy, FuzzStrategy::TrailerFrameCorruption) {
        fuzz_trailer_decoder(&fuzz_frame);
    }

    // Fuzz base64 decoders
    if matches!(fuzz_frame.strategy, FuzzStrategy::Base64Stream) {
        fuzz_base64_decoders(&fuzz_frame);
    }
});

fn run_fixed_canaries() {
    let mut compressed = BytesMut::from(&b"\x01\x00\x00\x00\x03abc"[..]);
    let codec = WebFrameCodec::with_max_size(MAX_FUZZ_FRAME_SIZE);
    match codec
        .decode(&mut compressed)
        .expect("valid compressed data frame must decode")
    {
        Some(WebFrame::Data { compressed, data }) => {
            assert!(compressed, "compression flag must be surfaced");
            assert_eq!(data.as_ref(), b"abc");
        }
        other => panic!("expected compressed data frame, got {other:?}"),
    }
    assert!(
        compressed.is_empty(),
        "successful frame decode must consume exactly one frame"
    );

    let mut reserved_flags = BytesMut::from(&b"\x02\x00\x00\x00\x00"[..]);
    let reserved_codec = WebFrameCodec::with_max_size(MAX_FUZZ_FRAME_SIZE);
    assert!(
        reserved_codec.decode(&mut reserved_flags).is_err(),
        "reserved gRPC-Web flag bits must fail closed"
    );
    assert!(
        reserved_codec.is_poisoned(),
        "reserved-flag rejection must poison the codec"
    );
    assert!(
        reserved_codec.decode(&mut reserved_flags).is_err(),
        "poisoned codec must reject repeated decode attempts"
    );

    let trailer = decode_trailers(b"grpc-status: 5\r\ngrpc-message: nope\r\n")
        .expect("well-formed trailers must decode");
    assert_eq!(trailer.status.code().as_i32(), 5);

    assert!(
        decode_trailers(b"grpc-status: 0\r\ngrpc-status: 14\r\n").is_err(),
        "duplicate grpc-status trailers must be rejected"
    );
    assert!(
        decode_trailers(b"grpc-status: 0\r\ntrace-bin: not_base64!\r\n").is_err(),
        "malformed binary metadata must reject the whole trailer block"
    );

    assert_eq!(
        base64_decode("aGVsbG8=").expect("valid base64 must decode"),
        b"hello"
    );
    assert!(
        base64_decode("not valid base64!!!").is_err(),
        "malformed base64 must be an observable error"
    );

    let mut stream = Base64StreamDecoder::new();
    let mut decoded = Vec::new();
    decoded.extend(
        stream
            .push(b"aG")
            .expect("partial base64 quartet must buffer"),
    );
    decoded.extend(stream.push(b"Vs").expect("completed quartet must decode"));
    decoded.extend(
        stream
            .push(b"bG8=")
            .expect("padded final quartet must decode and seal"),
    );
    assert_eq!(decoded, b"hello");
    assert!(stream.is_sealed(), "padding must seal the stream decoder");
    assert!(
        stream.push(b"extra").is_err(),
        "sealed stream decoder must reject additional chunks"
    );
    assert!(
        stream
            .finish()
            .expect("finish after seal must be idempotent")
            .is_empty()
    );
    assert!(
        stream
            .finish()
            .expect("second finish after seal must remain idempotent")
            .is_empty()
    );
}

fn observe_frame_result(
    codec: &WebFrameCodec,
    result: Result<Option<WebFrame>, impl core::fmt::Debug>,
) {
    match result {
        Ok(Some(WebFrame::Data { data, .. })) => {
            assert!(
                data.len() <= MAX_FUZZ_FRAME_SIZE,
                "decoded data frame exceeded fuzz max frame size"
            );
        }
        Ok(Some(WebFrame::Trailers(trailer))) => {
            let _ = trailer.status.code();
        }
        Ok(None) => {}
        Err(_) => {
            assert!(
                codec.is_poisoned(),
                "WebFrameCodec errors must leave the codec poisoned"
            );
        }
    }
}

fn observe_trailer_result(
    result: Result<asupersync::grpc::web::TrailerFrame, impl core::fmt::Debug>,
) {
    if let Ok(trailer) = result {
        let _ = trailer.status.code();
    }
}

/// Fuzz WebFrameCodec::decode() with structured frame data
fn fuzz_frame_codec(fuzz_frame: &FuzzWebFrame) {
    let frame_bytes = fuzz_frame.to_bytes();
    let mut buf = BytesMut::from(frame_bytes.as_slice());

    // Create codec with reasonable limits
    let codec = WebFrameCodec::with_max_size(MAX_FUZZ_FRAME_SIZE);

    // Decode and verify both no panics and basic parser contract outcomes.
    let result = codec.decode(&mut buf);
    observe_frame_result(&codec, result);

    // Test poisoned state handling
    if codec.is_poisoned() {
        // Subsequent decode should return poisoned error
        let mut buf2 = BytesMut::from(frame_bytes.as_slice());
        let result = codec.decode(&mut buf2);
        // Should be an error but not panic
        assert!(
            result.is_err(),
            "poisoned codec should reject further decoding"
        );
    }
}

/// Fuzz decode_trailers() directly with malformed header blocks
fn fuzz_trailer_decoder(fuzz_frame: &FuzzWebFrame) {
    let headers = fuzz_frame.build_trailer_headers();

    // Test with valid UTF-8 headers
    observe_trailer_result(decode_trailers(headers.as_bytes()));

    // Test with the raw payload (might be invalid UTF-8)
    observe_trailer_result(decode_trailers(&fuzz_frame.payload));

    // Test with empty input
    observe_trailer_result(decode_trailers(b""));

    // Test with headers that might have duplicate status/message
    let mut duplicate_headers = headers;
    duplicate_headers.push_str("grpc-status: 14\r\n"); // Duplicate status
    duplicate_headers.push_str("grpc-message: error\r\n");
    duplicate_headers.push_str("grpc-message: duplicate\r\n"); // Duplicate message
    assert!(
        decode_trailers(duplicate_headers.as_bytes()).is_err(),
        "duplicate status/message trailer block must fail closed"
    );
}

/// Fuzz base64 decoders (whole-input and streaming)
fn fuzz_base64_decoders(fuzz_frame: &FuzzWebFrame) {
    // Test whole-input base64 decoder
    if let Ok(base64_str) = std::str::from_utf8(&fuzz_frame.payload)
        && let Ok(decoded) = base64_decode(base64_str)
    {
        assert!(
            decoded.len() <= fuzz_frame.payload.len(),
            "base64 decoded bytes cannot exceed encoded input length"
        );
    }

    // Test streaming base64 decoder with chunked input
    let mut decoder = Base64StreamDecoder::new();

    for chunk in &fuzz_frame.base64_chunks {
        if decoder.is_sealed() {
            // Should reject further input after sealing
            let result = decoder.push(chunk);
            assert!(result.is_err(), "sealed decoder should reject push");
            break;
        }

        if let Ok(decoded) = decoder.push(chunk) {
            assert!(
                decoded.len() <= chunk.len() + 3,
                "stream base64 decoded chunk unexpectedly exceeded input plus carry"
            );
        }
    }

    // Finish the decoder (should not panic regardless of state)
    let _ = decoder.finish();

    // Test finish() on already-sealed decoder
    let _ = decoder.finish(); // Should be idempotent
}
