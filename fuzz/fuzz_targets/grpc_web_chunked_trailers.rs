//! Structure-aware fuzzer for gRPC-Web trailers framing under chunked transfer encoding.
//!
//! This fuzzer specifically targets the `Base64StreamDecoder` which handles
//! gRPC-Web-text mode streams that arrive as chunked HTTP bodies. The key
//! challenge is that HTTP chunks can split in the middle of base64 quartets,
//! requiring the decoder to buffer partial quartets across `push()` calls.
//!
//! **Target vulnerability areas:**
//! - Partial quartet buffering across chunk boundaries
//! - Padding (`=`) handling when split across chunks
//! - State transitions (sealed/unsealed) with various chunk patterns
//! - Error propagation for malformed base64 across chunk splits
//! - Trailer frame parsing after chunked base64 decoding
//!
//! **Structure-aware approach:** Rather than feeding random bytes, this fuzzer
//! generates realistic chunked scenarios with valid gRPC-Web trailer frames
//! encoded as base64, then splits them at strategic boundaries to exercise
//! the chunk reassembly logic.

#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

use asupersync::bytes::{Bytes, BytesMut};
use asupersync::grpc::status::{Code, Status};
use asupersync::grpc::streaming::Metadata;
use asupersync::grpc::web::{Base64StreamDecoder, WebFrameCodec, base64_encode, encode_trailers};

const MAX_CHUNKS: usize = 32;
const MAX_METADATA_ITEMS: usize = 8;
const MAX_KEY_LEN: usize = 32;
const MAX_VALUE_LEN: usize = 128;
const MAX_MESSAGE_LEN: usize = 256;

#[derive(Debug, Arbitrary)]
struct ChunkedTrailerInput {
    /// The trailer content to encode and chunk
    trailer_spec: TrailerSpec,
    /// How to split the base64 stream into chunks
    chunking_strategy: ChunkingStrategy,
    /// Whether to inject edge cases during chunking
    edge_cases: EdgeCases,
}

#[derive(Debug, Arbitrary)]
struct TrailerSpec {
    status_code: i32,
    status_message: String,
    metadata_entries: Vec<MetadataEntry>,
}

#[derive(Debug, Arbitrary)]
enum MetadataEntry {
    Ascii { key: String, value: String },
    Binary { key: String, value: Vec<u8> },
}

#[derive(Debug, Arbitrary)]
enum ChunkingStrategy {
    /// Split at every N characters
    FixedSize { chunk_size: u8 },
    /// Split at specific byte offsets
    SpecificOffsets { offsets: Vec<u8> },
    /// Split to exercise quartet boundaries (base64 groups of 4)
    QuartetBoundaries,
    /// Split to deliberately break quartets in the middle
    QuartetBreaking { break_positions: Vec<u8> },
    /// Random chunk sizes
    RandomSizes { sizes: Vec<u8> },
}

#[derive(Debug, Arbitrary)]
struct EdgeCases {
    /// Insert empty chunks between real chunks
    empty_chunks: bool,
    /// Try to split padding characters across chunks
    split_padding: bool,
    /// Inject invalid base64 characters at chunk boundaries
    boundary_corruption: Option<u8>,
    /// Test decoder state after finish() is called
    double_finish: bool,
    /// Try to push after decoder is sealed
    push_after_seal: bool,
}

fuzz_target!(|input: ChunkedTrailerInput| {
    fuzz_chunked_trailers(input);
});

fn fuzz_chunked_trailers(input: ChunkedTrailerInput) {
    // Step 1: Build a realistic gRPC-Web trailer frame
    let (status, metadata) = build_trailer_content(&input.trailer_spec);

    // Step 2: Encode trailer as binary gRPC-Web frame
    let mut frame_bytes = BytesMut::new();
    encode_trailers(&status, &metadata, &mut frame_bytes);

    // Step 3: Base64 encode the frame for gRPC-Web-text mode
    let base64_stream = base64_encode(&frame_bytes);

    // Step 4: Apply edge case modifications if requested
    let modified_stream = apply_edge_cases(&base64_stream, &input.edge_cases);

    // Step 5: Split into chunks according to strategy
    let chunks = split_into_chunks(&modified_stream, &input.chunking_strategy);

    // Step 6: Feed chunks to Base64StreamDecoder and test all state transitions
    exercise_chunked_decoding(chunks, &input.edge_cases);
}

fn build_trailer_content(spec: &TrailerSpec) -> (Status, Metadata) {
    // Sanitize status message to prevent invalid UTF-8
    let message = spec
        .status_message
        .chars()
        .filter(|c| c.is_ascii())
        .take(MAX_MESSAGE_LEN)
        .collect::<String>();

    let status = Status::new(Code::from_i32(spec.status_code), message);
    let mut metadata = Metadata::new();

    // Add metadata entries, respecting gRPC key validation rules
    for entry in spec.metadata_entries.iter().take(MAX_METADATA_ITEMS) {
        match entry {
            MetadataEntry::Ascii { key, value } => {
                if let Some(clean_key) = sanitize_metadata_key(key, false) {
                    let clean_value = sanitize_ascii_value(value);
                    assert!(
                        metadata.insert(clean_key.clone(), clean_value),
                        "sanitized ASCII metadata key {clean_key:?} should be accepted",
                    );
                }
            }
            MetadataEntry::Binary { key, value } => {
                if let Some(clean_key) = sanitize_metadata_key(key, true) {
                    let truncated: Vec<u8> = value.iter().copied().take(MAX_VALUE_LEN).collect();
                    assert!(
                        metadata.insert_bin(clean_key.clone(), Bytes::from(truncated)),
                        "sanitized binary metadata key {clean_key:?} should be accepted",
                    );
                }
            }
        }
    }

    (status, metadata)
}

fn sanitize_metadata_key(key: &str, for_binary: bool) -> Option<String> {
    // gRPC metadata keys must be lowercase ASCII + digits + `-`/`_`
    let mut clean: String = key
        .chars()
        .filter(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == '-' || *c == '_')
        .take(MAX_KEY_LEN)
        .collect();

    if clean.is_empty() {
        return None;
    }

    // Handle -bin suffix for binary metadata
    while clean.ends_with("-bin") {
        clean.truncate(clean.len() - 4);
    }

    if clean.is_empty() {
        return None;
    }

    if for_binary {
        clean.push_str("-bin");
    }

    Some(clean)
}

fn sanitize_ascii_value(value: &str) -> String {
    // Metadata insertion is fail-closed: only printable ASCII is accepted.
    // grpc-message percent-encoding has dedicated codec coverage elsewhere.
    value
        .chars()
        .filter(|c| matches!(*c, ' '..='~'))
        .take(MAX_VALUE_LEN)
        .collect()
}

fn apply_edge_cases(stream: &str, edge_cases: &EdgeCases) -> String {
    let mut modified = stream.to_string();

    // Inject boundary corruption if requested
    if let Some(bad_char) = edge_cases.boundary_corruption
        && !modified.is_empty()
        && (bad_char as char).is_ascii()
    {
        // Insert invalid character at a strategic position
        let pos = (bad_char as usize) % modified.len();
        modified.insert(pos, bad_char as char);
    }

    modified
}

fn split_into_chunks(stream: &str, strategy: &ChunkingStrategy) -> Vec<String> {
    if stream.is_empty() {
        return vec![];
    }

    let bytes = stream.as_bytes();
    let mut chunks = Vec::new();

    match strategy {
        ChunkingStrategy::FixedSize { chunk_size } => {
            let size = (*chunk_size as usize).max(1);
            for chunk in bytes.chunks(size) {
                chunks.push(String::from_utf8_lossy(chunk).to_string());
            }
        }

        ChunkingStrategy::SpecificOffsets { offsets } => {
            let mut start = 0;
            for &offset in offsets.iter().take(MAX_CHUNKS) {
                let end = (start + offset as usize).min(bytes.len());
                if start < end {
                    chunks.push(String::from_utf8_lossy(&bytes[start..end]).to_string());
                    start = end;
                }
            }
            if start < bytes.len() {
                chunks.push(String::from_utf8_lossy(&bytes[start..]).to_string());
            }
        }

        ChunkingStrategy::QuartetBoundaries => {
            // Split exactly at base64 quartet boundaries (every 4 characters)
            for chunk in bytes.chunks(4) {
                chunks.push(String::from_utf8_lossy(chunk).to_string());
            }
        }

        ChunkingStrategy::QuartetBreaking { break_positions } => {
            // Deliberately split in the middle of quartets to test partial buffering
            let mut start = 0;
            for &pos in break_positions.iter().take(MAX_CHUNKS) {
                let offset = (pos % 4) + 1; // 1-3 chars into a quartet
                let end = (start + offset as usize).min(bytes.len());
                if start < end {
                    chunks.push(String::from_utf8_lossy(&bytes[start..end]).to_string());
                    start = end;
                }
            }
            if start < bytes.len() {
                chunks.push(String::from_utf8_lossy(&bytes[start..]).to_string());
            }
        }

        ChunkingStrategy::RandomSizes { sizes } => {
            let mut start = 0;
            for &size in sizes.iter().take(MAX_CHUNKS) {
                let chunk_size = (size as usize).max(1);
                let end = (start + chunk_size).min(bytes.len());
                if start < end {
                    chunks.push(String::from_utf8_lossy(&bytes[start..end]).to_string());
                    start = end;
                }
            }
            if start < bytes.len() {
                chunks.push(String::from_utf8_lossy(&bytes[start..]).to_string());
            }
        }
    }

    // Ensure we have at least one chunk to avoid empty test cases
    if chunks.is_empty() && !stream.is_empty() {
        chunks.push(stream.to_string());
    }

    chunks
}

fn exercise_chunked_decoding(chunks: Vec<String>, edge_cases: &EdgeCases) {
    let mut decoder = Base64StreamDecoder::new();
    let mut decoded_data = Vec::new();

    // Feed chunks to decoder
    for (i, chunk) in chunks.iter().enumerate().take(MAX_CHUNKS) {
        // Insert empty chunks if edge case is enabled
        if edge_cases.empty_chunks && i > 0 {
            observe_stream_push_result(decoder.push(b""), "empty chunk push", 0);
        }

        match decoder.push(chunk.as_bytes()) {
            Ok(data) => decoded_data.extend_from_slice(&data),
            Err(_) => {
                // Decoder rejected chunk - this is expected for malformed input.
                // Key property: decoder state should remain consistent.
                let was_sealed_before = decoder.is_sealed();

                // Try to push again to verify error handling is consistent
                let _second_result = decoder.push(b"");
                let is_sealed_after = decoder.is_sealed();

                // Invariant: seal state should not change on repeated errors
                if was_sealed_before && !is_sealed_after {
                    panic!("Decoder seal state became inconsistent after error");
                }

                return; // Stop on first error (expected behavior)
            }
        }

        // Test split padding edge case - try to push padding character separately
        if edge_cases.split_padding && chunk.contains('=') && !decoder.is_sealed() {
            observe_stream_push_result(decoder.push(b"="), "split padding push", 2);
        }
    }

    // Finalize decoding
    match decoder.finish() {
        Ok(trailing) => decoded_data.extend_from_slice(&trailing),
        Err(_) => return, // Expected for malformed streams
    }

    // Test double finish edge case
    if edge_cases.double_finish
        && let Ok(data) = decoder.finish()
    {
        // Second finish should return empty and not panic
        if !data.is_empty() {
            panic!("Second finish() returned non-empty data");
        }
    }

    // Test push after seal edge case
    if edge_cases.push_after_seal && decoder.is_sealed() {
        assert!(
            decoder.push(b"extra").is_err(),
            "Push after seal should fail"
        );
    }

    // If we got valid base64 data, try to decode it as a gRPC-Web frame
    if !decoded_data.is_empty() {
        validate_decoded_trailer_frame(&decoded_data);
    }
}

fn observe_stream_push_result(
    result: Result<Vec<u8>, impl core::fmt::Debug>,
    context: &str,
    max_decoded_len: usize,
) {
    match result {
        Ok(decoded) => {
            assert!(
                decoded.len() <= max_decoded_len,
                "{context}: decoded {} bytes, expected at most {}",
                decoded.len(),
                max_decoded_len
            );
        }
        Err(err) => {
            let diagnostic = format!("{err:?}");
            assert!(
                !diagnostic.trim().is_empty(),
                "{context}: push failure should expose diagnostics"
            );
        }
    }
}

fn validate_decoded_trailer_frame(data: &[u8]) {
    // Try to decode as gRPC-Web frame using WebFrameCodec
    let codec = WebFrameCodec::new();
    let mut buf = BytesMut::from(data);

    match codec.decode(&mut buf) {
        Ok(Some(frame)) => {
            // Successfully parsed a frame - verify it's a trailer
            use asupersync::grpc::web::WebFrame;
            if let WebFrame::Trailers(trailers) = frame {
                // Validate trailer invariants
                let _ = trailers.status.code();
                let _ = trailers.status.message();

                // Verify metadata consistency
                for (key, _value) in trailers.metadata.iter() {
                    // Key should be valid metadata key format
                    assert!(
                        !key.is_empty() && key.is_ascii(),
                        "Invalid metadata key format after chunked decoding: {:?}",
                        key
                    );
                }
            }
        }
        Ok(None) => {
            // Partial frame - acceptable for fuzzing
        }
        Err(_) => {
            // Frame parsing failed - this is expected for malformed inputs
            // but we've already validated that the chunked base64 decoding worked
        }
    }
}
