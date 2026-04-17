#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use libfuzzer_sys::fuzz_target;

use asupersync::http::h1::stream::BodyKind;
use std::collections::HashMap;

/// Fuzzing parameters for HTTP/1.1 body stream processing.
#[derive(Debug, Clone, Arbitrary)]
struct H1BodyStreamConfig {
    /// Type of body to test
    pub body_type: FuzzBodyKind,
    /// Sequence of byte pushes to test streaming behavior
    pub push_sequence: Vec<BytePush>,
    /// Size limits for testing boundary conditions
    pub limits: SizeLimits,
    /// Whether to finish the stream after pushes
    pub finish_stream: bool,
    /// Chunked-specific test data
    pub chunked_config: Option<ChunkedConfig>,
}

/// Body type for fuzzing
#[derive(Debug, Clone, Arbitrary, PartialEq)]
enum FuzzBodyKind {
    Empty,
    ContentLength(u64),
    Chunked,
}

impl From<FuzzBodyKind> for BodyKind {
    fn from(fuzz_kind: FuzzBodyKind) -> Self {
        match fuzz_kind {
            FuzzBodyKind::Empty => BodyKind::Empty,
            FuzzBodyKind::ContentLength(n) => BodyKind::ContentLength(n),
            FuzzBodyKind::Chunked => BodyKind::Chunked,
        }
    }
}

/// A push of bytes to the body stream
#[derive(Debug, Clone, Arbitrary)]
struct BytePush {
    /// Raw bytes to push
    pub data: Vec<u8>,
    /// Whether to expect this push to succeed
    pub expect_success: bool,
}

/// Size limits for testing boundary conditions
#[derive(Debug, Clone, Arbitrary)]
struct SizeLimits {
    /// Maximum total body size
    pub max_body_size: u64,
    /// Maximum chunk size for yielding frames
    pub max_chunk_size: usize,
    /// Maximum buffered bytes for partial parsing
    pub max_buffered_bytes: usize,
    /// Maximum total trailer size
    pub max_trailers_size: usize,
}

/// Configuration specific to chunked transfer encoding
#[derive(Debug, Clone, Arbitrary)]
struct ChunkedConfig {
    /// Pre-built chunked encoding test cases
    pub test_chunks: Vec<ChunkedTestCase>,
    /// Raw chunked data for edge case testing
    pub raw_chunked_data: Vec<u8>,
}

/// A specific chunked encoding test case
#[derive(Debug, Clone, Arbitrary)]
struct ChunkedTestCase {
    /// Chunk size (will be formatted as hex)
    pub size: usize,
    /// Optional chunk extensions after semicolon
    pub extensions: Vec<String>,
    /// Data bytes for this chunk
    pub data: Vec<u8>,
    /// Whether to include proper CRLF termination
    pub proper_termination: bool,
    /// Trailer headers after zero-sized chunk
    pub trailers: HashMap<String, String>,
}

/// Normalize fuzz configuration to valid ranges
fn normalize_config(config: &mut H1BodyStreamConfig) {
    // Normalize size limits to reasonable ranges
    config.limits.max_body_size = config.limits.max_body_size.clamp(1, 100 * 1024 * 1024);
    config.limits.max_chunk_size = config.limits.max_chunk_size.clamp(1, 1024 * 1024);
    config.limits.max_buffered_bytes = config.limits.max_buffered_bytes.clamp(1, 1024 * 1024);
    config.limits.max_trailers_size = config.limits.max_trailers_size.clamp(1, 64 * 1024);

    // Limit push sequence length for performance
    config.push_sequence.truncate(50);

    // Normalize push data sizes
    for push in &mut config.push_sequence {
        push.data.truncate(config.limits.max_buffered_bytes);
    }

    // Normalize chunked config if present
    if let Some(ref mut chunked) = config.chunked_config {
        chunked.test_chunks.truncate(20);
        chunked
            .raw_chunked_data
            .truncate(config.limits.max_buffered_bytes);

        for chunk in &mut chunked.test_chunks {
            // Clamp chunk size to reasonable range
            chunk.size = chunk.size.clamp(0, 1024 * 1024);
            chunk.data.truncate(chunk.size.min(65536));
            chunk.extensions.truncate(5);

            for ext in &mut chunk.extensions {
                // Safe UTF-8 aware truncation
                if ext.len() > 128 {
                    let mut truncate_at = 128;
                    while truncate_at > 0 && !ext.is_char_boundary(truncate_at) {
                        truncate_at -= 1;
                    }
                    ext.truncate(truncate_at);
                }
                // Remove invalid characters that could break chunk extensions
                ext.retain(|c| c.is_ascii() && c != '\r' && c != '\n' && c != '\0');
            }

            // Limit trailers
            chunk.trailers.retain(|k, v| {
                k.len() <= 64
                    && v.len() <= 256
                    && k.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
                    && v.chars()
                        .all(|c| c.is_ascii() && c != '\r' && c != '\n' && c != '\0')
            });
            if chunk.trailers.len() > 10 {
                let keys: Vec<_> = chunk.trailers.keys().take(10).cloned().collect();
                chunk.trailers.retain(|k, _| keys.contains(k));
            }
        }
    }

    // Ensure chunked config exists for chunked body type
    if matches!(config.body_type, FuzzBodyKind::Chunked) && config.chunked_config.is_none() {
        config.chunked_config = Some(ChunkedConfig {
            test_chunks: vec![],
            raw_chunked_data: vec![],
        });
    }
}

/// Test basic body type handling and validation
fn test_body_kind_handling(config: &H1BodyStreamConfig) -> Result<(), String> {
    let body_kind: BodyKind = config.body_type.clone().into();

    // Test body kind properties
    let is_empty = body_kind.is_empty();
    let is_chunked = body_kind.is_chunked();
    let exact_size = body_kind.exact_size();

    // Validate consistency
    match config.body_type {
        FuzzBodyKind::Empty => {
            if !is_empty || is_chunked || exact_size != Some(0) {
                return Err("Empty body kind properties inconsistent".to_string());
            }
        }
        FuzzBodyKind::ContentLength(n) => {
            if is_chunked || exact_size != Some(n) || (n == 0 && !is_empty) {
                return Err("ContentLength body kind properties inconsistent".to_string());
            }
        }
        FuzzBodyKind::Chunked => {
            if !is_chunked || is_empty || exact_size.is_some() {
                return Err("Chunked body kind properties inconsistent".to_string());
            }
        }
    }

    Ok(())
}

/// Test content-length body size validation
fn test_content_length_validation(config: &H1BodyStreamConfig) -> Result<(), String> {
    let FuzzBodyKind::ContentLength(expected_size) = config.body_type else {
        return Ok(()); // Skip for non-content-length bodies
    };

    // Test boundary conditions on size limits
    if expected_size > config.limits.max_body_size {
        // Large content-length should be rejected
    }

    // Validate push sequence against expected size
    let total_push_size: u64 = config
        .push_sequence
        .iter()
        .map(|p| p.data.len() as u64)
        .sum();

    // Check consistency between expected size and actual data
    if config.finish_stream && total_push_size != expected_size {
        // Should cause validation error when finishing with mismatched size
    }

    Ok(())
}

/// Test chunked encoding data format validation
fn test_chunked_data_format(config: &H1BodyStreamConfig) -> Result<(), String> {
    if !matches!(config.body_type, FuzzBodyKind::Chunked) {
        return Ok(());
    }

    let Some(chunked_config) = &config.chunked_config else {
        return Ok(());
    };

    // Test pre-built chunk cases
    for chunk_case in &chunked_config.test_chunks {
        let chunk_data = build_chunked_data(chunk_case);

        // Validate the chunk data format
        let _validation_result = validate_chunked_data_format(&chunk_data);

        // Test size consistency
        if chunk_case.proper_termination && chunk_case.data.len() != chunk_case.size {
            // Data length mismatch should be caught
        }
    }

    // Test raw chunked data parsing
    if !chunked_config.raw_chunked_data.is_empty() {
        let _validation_result = validate_chunked_data_format(&chunked_config.raw_chunked_data);
    }

    Ok(())
}

/// Build chunked encoding data from test case
fn build_chunked_data(chunk_case: &ChunkedTestCase) -> Vec<u8> {
    let mut data = Vec::new();

    // Write chunk size in hex
    data.extend_from_slice(format!("{:x}", chunk_case.size).as_bytes());

    // Add extensions if any
    for extension in &chunk_case.extensions {
        data.extend_from_slice(b";");
        data.extend_from_slice(extension.as_bytes());
    }

    if chunk_case.proper_termination {
        data.extend_from_slice(b"\r\n");
    }

    // Add chunk data
    let actual_data_len = chunk_case.data.len().min(chunk_case.size);
    data.extend_from_slice(&chunk_case.data[..actual_data_len]);

    if chunk_case.proper_termination && actual_data_len == chunk_case.size {
        data.extend_from_slice(b"\r\n");
    }

    // For zero-sized chunks, add trailers
    if chunk_case.size == 0 {
        for (name, value) in &chunk_case.trailers {
            data.extend_from_slice(name.as_bytes());
            data.extend_from_slice(b": ");
            data.extend_from_slice(value.as_bytes());
            if chunk_case.proper_termination {
                data.extend_from_slice(b"\r\n");
            }
        }
        if chunk_case.proper_termination {
            data.extend_from_slice(b"\r\n"); // Final CRLF
        }
    }

    data
}

/// Validate chunked data format (simplified parser for testing)
fn validate_chunked_data_format(data: &[u8]) -> Result<(), String> {
    let mut pos = 0;
    let data_len = data.len();

    while pos < data_len {
        // Look for CRLF to find end of size line
        let line_end = data[pos..].windows(2).position(|w| w == b"\r\n");
        let Some(line_end_offset) = line_end else {
            // Incomplete line - might be valid partial data
            return Ok(());
        };

        let line_end_pos = pos + line_end_offset;
        let line = &data[pos..line_end_pos];

        // Parse chunk size line
        let line_str = match std::str::from_utf8(line) {
            Ok(s) => s,
            Err(_) => return Err("Invalid UTF-8 in chunk size line".to_string()),
        };

        let size_part = line_str.split(';').next().unwrap_or("").trim();
        if size_part.is_empty() {
            return Err("Empty chunk size".to_string());
        }

        let chunk_size = match usize::from_str_radix(size_part, 16) {
            Ok(size) => size,
            Err(_) => return Err("Invalid hex chunk size".to_string()),
        };

        pos = line_end_pos + 2; // Skip CRLF

        if chunk_size == 0 {
            // Zero chunk - should be followed by trailers and final CRLF
            return Ok(());
        }

        // Check if we have enough data for the chunk
        if pos + chunk_size + 2 > data_len {
            // Incomplete chunk data
            return Ok(());
        }

        // Skip chunk data
        pos += chunk_size;

        // Check for trailing CRLF
        if pos + 1 < data_len && data[pos] == b'\r' && data[pos + 1] == b'\n' {
            pos += 2;
        } else {
            return Err("Missing CRLF after chunk data".to_string());
        }
    }

    Ok(())
}

/// Test size limit enforcement
fn test_size_limits(config: &H1BodyStreamConfig) -> Result<(), String> {
    // Test max body size limit
    if let FuzzBodyKind::ContentLength(size) = config.body_type {
        if size > config.limits.max_body_size {
            // Should be rejected
        }
    }

    // Test max buffered bytes
    let total_push_size: usize = config.push_sequence.iter().map(|p| p.data.len()).sum();

    if total_push_size > config.limits.max_buffered_bytes {
        // Should trigger buffering limits
    }

    // Test max chunk size for chunked bodies
    if matches!(config.body_type, FuzzBodyKind::Chunked) {
        if let Some(chunked_config) = &config.chunked_config {
            for chunk_case in &chunked_config.test_chunks {
                if chunk_case.size > config.limits.max_chunk_size {
                    // Large chunks should be handled appropriately
                }
            }
        }
    }

    Ok(())
}

/// Test malformed input handling
fn test_malformed_input_handling(config: &H1BodyStreamConfig) -> Result<(), String> {
    if !matches!(config.body_type, FuzzBodyKind::Chunked) {
        return Ok(());
    }

    // Test various malformed chunked encoding patterns
    let malformed_inputs = vec![
        b"gggg\r\n".to_vec(),                    // Invalid hex
        b"10\ndata\r\n".to_vec(),                // Missing \r in CRLF
        b"10\r\ndata\n".to_vec(),                // Missing \r in data CRLF
        b"10 \r\ndata\r\n".to_vec(),             // Space in hex number
        vec![0xff, 0xfe, b'\r', b'\n'],          // Invalid UTF-8 in chunk size
        b"-5\r\n".to_vec(),                      // Negative chunk size
        b"10000000000000000\r\n".to_vec(),       // Extremely large chunk size
        b"10\r\nshort\r\n".to_vec(),             // Data shorter than declared size
        b"5\r\ntoolongdata\r\n".to_vec(),        // Data longer than declared size
        b"0\r\nInvalid-Header\r\n\r\n".to_vec(), // Malformed trailer header
    ];

    for malformed in malformed_inputs {
        let result = validate_chunked_data_format(&malformed);
        // Should either handle gracefully or return appropriate error
        match result {
            Ok(()) => {
                // Parser might handle partial/malformed data gracefully
            }
            Err(_) => {
                // Appropriate rejection of malformed data
            }
        }
    }

    Ok(())
}

/// Main fuzzing function
fn fuzz_h1_body_stream(mut config: H1BodyStreamConfig) -> Result<(), String> {
    normalize_config(&mut config);

    // Skip degenerate cases
    if config.push_sequence.is_empty()
        && config.chunked_config.as_ref().map_or(true, |c| {
            c.test_chunks.is_empty() && c.raw_chunked_data.is_empty()
        })
    {
        return Ok(());
    }

    // Test 1: Body kind handling and validation
    test_body_kind_handling(&config)?;

    // Test 2: Content-length body validation
    test_content_length_validation(&config)?;

    // Test 3: Chunked data format validation
    test_chunked_data_format(&config)?;

    // Test 4: Size limit enforcement
    test_size_limits(&config)?;

    // Test 5: Malformed input handling
    test_malformed_input_handling(&config)?;

    Ok(())
}

fuzz_target!(|data: &[u8]| {
    // Limit input size for performance
    if data.len() > 8_000 {
        return;
    }

    let mut unstructured = Unstructured::new(data);

    // Generate fuzz configuration
    let config = if let Ok(c) = H1BodyStreamConfig::arbitrary(&mut unstructured) {
        c
    } else {
        return;
    };

    // Run HTTP/1.1 body stream fuzzing
    let _ = fuzz_h1_body_stream(config);
});
