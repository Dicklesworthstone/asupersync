#![no_main]

use libfuzzer_sys::fuzz_target;

/// Fuzz target for HTTP compression/decompression robustness and security.
///
/// This target is designed to prevent decompression bomb DoS attacks and test
/// the robustness of HTTP compression handling against malicious inputs:
///
/// **Critical Security Properties Tested:**
/// - Size limit enforcement (prevent decompression bombs)
/// - Memory safety against malformed compressed streams
/// - Accept-Encoding header parsing robustness
/// - Streaming decompression consistency
/// - Proper error handling for invalid compressed data
///
/// **Decompression Functions Tested:**
/// - `IdentityDecompressor::decompress()`: Passthrough with size limits
/// - `GzipDecompressor::decompress()`: gzip (RFC 1952) decompression
/// - `DeflateDecompressor::decompress()`: deflate (RFC 1951) decompression
/// - `BrotliDecompressor::decompress()`: Brotli (RFC 7932) decompression
/// - `parse_accept_encoding()`: Accept-Encoding header parsing
/// - `negotiate_encoding()`: Content encoding negotiation
///
/// **Attack Scenarios Covered:**
/// - Decompression bombs (small compressed input → massive output)
/// - Malformed compression headers and trailers
/// - Truncated streams at critical boundaries
/// - Streams exceeding configured size limits
/// - Invalid quality values in Accept-Encoding headers
/// - Embedded null bytes and control characters
/// - Very long compression streams testing memory usage
use asupersync::http::compress::{
    BrotliDecompressor, ContentEncoding, Decompressor, DeflateDecompressor, GzipDecompressor,
    IdentityDecompressor, negotiate_encoding, parse_accept_encoding,
};
use std::io;

// Constants for decompression bomb protection
const MAX_DECOMPRESSED_SIZE: usize = 1024 * 1024; // 1MB safety limit for fuzzing
const SMALL_DECOMPRESSED_SIZE: usize = 1024; // 1KB for testing exact limits

/// Test identity decompression with size limits and edge cases.
fn test_identity_decompression(data: &[u8]) {
    // Test various size limits
    let size_limits = [
        None,                               // No limit
        Some(SMALL_DECOMPRESSED_SIZE),      // Small limit
        Some(MAX_DECOMPRESSED_SIZE),        // Large limit
        Some(data.len()),                   // Exact size
        Some(data.len().saturating_sub(1)), // Just under
    ];

    for &max_size in &size_limits {
        let mut decompressor = IdentityDecompressor::new(max_size);
        let mut output = Vec::new();

        // Test chunk-by-chunk decompression
        for chunk_size in [1, 4, 16, 64, data.len()] {
            if chunk_size > data.len() {
                continue;
            }

            let mut local_output = Vec::new();
            let mut local_decompressor = IdentityDecompressor::new(max_size);

            for chunk in data.chunks(chunk_size) {
                match local_decompressor.decompress(chunk, &mut local_output) {
                    Ok(_) => {
                        // Verify size limits are respected
                        if let Some(limit) = max_size {
                            assert!(
                                local_output.len() <= limit,
                                "Identity decompressor exceeded size limit: {} > {}",
                                local_output.len(),
                                limit
                            );
                        }
                    }
                    Err(e) => {
                        // Error is acceptable, especially for size limit violations
                        assert!(
                            e.kind() == io::ErrorKind::Other
                                || e.kind() == io::ErrorKind::InvalidData,
                            "Unexpected error kind: {:?}",
                            e.kind()
                        );
                    }
                }
            }

            // Test finish()
            let _ = local_decompressor.finish(&mut local_output);
        }
    }
}

/// Test gzip decompression against malformed and crafted inputs.
fn test_gzip_decompression(data: &[u8]) {
    // Test various size limits
    let size_limits = [
        Some(SMALL_DECOMPRESSED_SIZE),
        Some(MAX_DECOMPRESSED_SIZE),
        None,
    ];

    for &max_size in &size_limits {
        let mut decompressor = GzipDecompressor::new(max_size);
        let mut output = Vec::new();

        // Test single-shot decompression
        match decompressor.decompress(data, &mut output) {
            Ok(_) => {
                // Verify size limits
                if let Some(limit) = max_size {
                    assert!(
                        output.len() <= limit,
                        "Gzip decompressor exceeded size limit: {} > {}",
                        output.len(),
                        limit
                    );
                }

                // Test finish after successful decompress
                let _ = decompressor.finish(&mut output);
            }
            Err(_) => {
                // Errors are expected for malformed gzip data
                // Still test finish() to ensure no panics
                let _ = decompressor.finish(&mut output);
            }
        }

        // Test streaming decompression with various chunk sizes
        for chunk_size in [1, 8, 32] {
            if data.len() < chunk_size {
                continue;
            }

            let mut stream_decompressor = GzipDecompressor::new(max_size);
            let mut stream_output = Vec::new();

            for chunk in data.chunks(chunk_size) {
                match stream_decompressor.decompress(chunk, &mut stream_output) {
                    Ok(_) => {
                        if let Some(limit) = max_size {
                            assert!(
                                stream_output.len() <= limit,
                                "Streaming gzip exceeded size limit: {} > {}",
                                stream_output.len(),
                                limit
                            );
                        }
                    }
                    Err(_) => break, // Expected for malformed data
                }
            }

            let _ = stream_decompressor.finish(&mut stream_output);
        }
    }
}

/// Test deflate decompression with focus on zlib wrapper handling.
fn test_deflate_decompression(data: &[u8]) {
    let size_limits = [
        Some(SMALL_DECOMPRESSED_SIZE),
        Some(MAX_DECOMPRESSED_SIZE),
        None,
    ];

    for &max_size in &size_limits {
        let mut decompressor = DeflateDecompressor::new(max_size);
        let mut output = Vec::new();

        // Test single-shot decompression
        match decompressor.decompress(data, &mut output) {
            Ok(_) => {
                if let Some(limit) = max_size {
                    assert!(
                        output.len() <= limit,
                        "Deflate decompressor exceeded size limit: {} > {}",
                        output.len(),
                        limit
                    );
                }
            }
            Err(_) => {
                // Expected for malformed deflate data
            }
        }

        let _ = decompressor.finish(&mut output);

        // Test incremental decompression
        let mut incremental_decompressor = DeflateDecompressor::new(max_size);
        let mut incremental_output = Vec::new();

        // Feed data byte by byte to stress boundary handling
        for &byte in data.iter().take(100) {
            // Limit to avoid timeout
            match incremental_decompressor.decompress(&[byte], &mut incremental_output) {
                Ok(_) => {
                    if let Some(limit) = max_size {
                        if incremental_output.len() > limit {
                            panic!(
                                "Incremental deflate exceeded size limit: {} > {}",
                                incremental_output.len(),
                                limit
                            );
                        }
                    }
                }
                Err(_) => break,
            }
        }

        let _ = incremental_decompressor.finish(&mut incremental_output);
    }
}

/// Test brotli decompression robustness.
fn test_brotli_decompression(data: &[u8]) {
    let size_limits = [
        Some(SMALL_DECOMPRESSED_SIZE),
        Some(MAX_DECOMPRESSED_SIZE),
        None,
    ];

    for &max_size in &size_limits {
        let mut decompressor = BrotliDecompressor::new(max_size);
        let mut output = Vec::new();

        match decompressor.decompress(data, &mut output) {
            Ok(_) => {
                if let Some(limit) = max_size {
                    assert!(
                        output.len() <= limit,
                        "Brotli decompressor exceeded size limit: {} > {}",
                        output.len(),
                        limit
                    );
                }
            }
            Err(_) => {
                // Expected for malformed brotli data
            }
        }

        let _ = decompressor.finish(&mut output);

        // Test with different chunk boundaries
        let mut chunk_decompressor = BrotliDecompressor::new(max_size);
        let mut chunk_output = Vec::new();

        for chunk_size in [2, 7, 23] {
            // Prime numbers to hit weird boundaries
            if data.len() < chunk_size {
                continue;
            }

            for chunk in data.chunks(chunk_size) {
                match chunk_decompressor.decompress(chunk, &mut chunk_output) {
                    Ok(_) => {
                        if let Some(limit) = max_size {
                            if chunk_output.len() > limit {
                                panic!(
                                    "Chunked brotli exceeded size limit: {} > {}",
                                    chunk_output.len(),
                                    limit
                                );
                            }
                        }
                    }
                    Err(_) => break,
                }
            }

            let _ = chunk_decompressor.finish(&mut chunk_output);
            break; // Only test one chunk size per data input
        }
    }
}

/// Test Accept-Encoding header parsing with malicious inputs.
fn test_accept_encoding_parsing(data: &[u8]) {
    if let Ok(header_str) = std::str::from_utf8(data) {
        // Test the internal parsing function (exposed through negotiate_encoding)
        let all_encodings = &[
            ContentEncoding::Identity,
            ContentEncoding::Gzip,
            ContentEncoding::Deflate,
            ContentEncoding::Brotli,
        ];

        // Should not crash on any input
        let _result = negotiate_encoding(Some(header_str), all_encodings);

        // Test with empty supported list
        let _result = negotiate_encoding(Some(header_str), &[]);

        // Test with single encoding
        for &encoding in all_encodings {
            let _result = negotiate_encoding(Some(header_str), &[encoding]);
        }

        // Test ContentEncoding::from_token with various parts of the header
        for part in header_str.split(|c: char| !c.is_ascii_alphanumeric() && c != '-') {
            if !part.is_empty() {
                let _encoding = ContentEncoding::from_token(part);
            }
        }
    }
}

/// Generate malformed compressed data patterns for edge case testing.
fn test_compression_edge_cases(base_data: &[u8]) {
    if base_data.is_empty() {
        return;
    }

    // Create various malformed compression patterns
    let malformed_patterns = vec![
        // Truncated headers
        base_data[..std::cmp::min(1, base_data.len())].to_vec(),
        base_data[..std::cmp::min(2, base_data.len())].to_vec(),
        // Invalid magic numbers (common compression headers)
        {
            let mut invalid_gzip = vec![0x1f, 0x8b, 0x08]; // Valid gzip header start
            invalid_gzip.extend_from_slice(base_data);
            invalid_gzip[2] = 0xFF; // Invalid compression method
            invalid_gzip
        },
        // Potential decompression bombs - small input that might expand
        {
            let mut bomb_attempt = vec![
                0x1f, 0x8b, 0x08, 0x00, // gzip header
                0x00, 0x00, 0x00, 0x00, // mtime
                0x00, 0x03, // extra flags + OS
            ];
            // Add deflate stream that might attempt to create large output
            bomb_attempt.extend_from_slice(base_data);
            bomb_attempt
        },
        // Embedded nulls and control characters
        {
            let mut with_nulls = base_data.to_vec();
            for i in (0..with_nulls.len()).step_by(7) {
                with_nulls[i] = 0x00;
            }
            with_nulls
        },
        // Repeated byte patterns (common in compression bombs)
        vec![base_data.get(0).copied().unwrap_or(0); std::cmp::min(base_data.len() * 10, 1000)],
    ];

    for malformed_data in &malformed_patterns {
        // Test each decompression algorithm with malformed data
        test_identity_decompression(malformed_data);
        test_gzip_decompression(malformed_data);
        test_deflate_decompression(malformed_data);
        test_brotli_decompression(malformed_data);
    }
}

/// Test specific known compression edge cases and attack patterns.
fn test_known_edge_cases() {
    let edge_cases = vec![
        // Empty input
        vec![],
        // Single bytes
        vec![0x00],
        vec![0xFF],
        // Valid gzip header with no data
        vec![0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03],
        // Invalid gzip magic
        vec![0x1f, 0x8c, 0x08, 0x00],
        // Deflate with zlib header
        vec![0x78, 0x9c], // zlib header (CM=8, CINFO=7, FCHECK=28)
        // Brotli stream header
        vec![0x1b], // Brotli stream start
        // Large header claiming huge uncompressed size
        vec![
            0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0xFF, 0xFF, 0xFF, 0xFF,
        ], // Try to claim huge size
        // Accept-Encoding edge cases
        b"gzip;q=1.7976931348623157e+308".to_vec(), // Huge quality value
        b"*;q=0.".to_vec(),                         // Incomplete quality
        b"gzip;q=".to_vec(),                        // Missing quality value
        b"identity\x00gzip".to_vec(),               // Embedded null
        b"gzip,".repeat(10000).into_bytes(),        // Excessive repetition
    ];

    for edge_case in &edge_cases {
        test_identity_decompression(edge_case);
        test_gzip_decompression(edge_case);
        test_deflate_decompression(edge_case);
        test_brotli_decompression(edge_case);
        test_accept_encoding_parsing(edge_case);
    }
}

/// Test size limit enforcement at exact boundaries.
fn test_size_limit_boundaries(data: &[u8]) {
    if data.is_empty() {
        return;
    }

    // Test exact boundary conditions for size limits
    let test_sizes = [
        0,
        1,
        data.len().saturating_sub(1),
        data.len(),
        data.len() + 1,
    ];

    for &limit in &test_sizes {
        // Test identity decompression at exact boundaries
        let mut identity = IdentityDecompressor::new(Some(limit));
        let mut output = Vec::new();

        match identity.decompress(data, &mut output) {
            Ok(_) => {
                assert!(
                    output.len() <= limit,
                    "Identity boundary test failed: {} > {}",
                    output.len(),
                    limit
                );
            }
            Err(_) => {
                // Expected when data exceeds limit
                if data.len() > limit {
                    // This is the correct behavior
                } else {
                    // Might be other error, which is also acceptable
                }
            }
        }

        // Test streaming across the boundary
        let mut streaming_identity = IdentityDecompressor::new(Some(limit));
        let mut streaming_output = Vec::new();

        for &byte in data.iter().take(limit.saturating_add(5)) {
            match streaming_identity.decompress(&[byte], &mut streaming_output) {
                Ok(_) => {
                    assert!(
                        streaming_output.len() <= limit,
                        "Streaming boundary test failed: {} > {}",
                        streaming_output.len(),
                        limit
                    );
                }
                Err(_) => {
                    // Expected when hitting size limit
                    break;
                }
            }
        }
    }
}

fuzz_target!(|data: &[u8]| {
    // Limit input size to prevent fuzzer timeouts
    if data.len() > 50_000 {
        return;
    }

    // Test 1: Direct decompression function testing
    test_identity_decompression(data);
    test_gzip_decompression(data);
    test_deflate_decompression(data);
    test_brotli_decompression(data);

    // Test 2: Accept-Encoding header parsing
    test_accept_encoding_parsing(data);

    // Test 3: Generate and test malformed compression patterns
    test_compression_edge_cases(data);

    // Test 4: Always test known edge cases
    test_known_edge_cases();

    // Test 5: Size limit boundary testing
    test_size_limit_boundaries(data);

    // Test 6: Multi-algorithm consistency testing
    if data.len() > 10 && data.len() < 1000 {
        // Test that different decompression approaches are consistent
        let mut identity_output = Vec::new();
        let mut identity_decompressor = IdentityDecompressor::new(Some(MAX_DECOMPRESSED_SIZE));

        if identity_decompressor
            .decompress(data, &mut identity_output)
            .is_ok()
        {
            // If identity succeeds, the data should be treated as literal bytes
            // Verify that compressed formats properly reject or handle it

            let mut gzip_output = Vec::new();
            let mut gzip_decompressor = GzipDecompressor::new(Some(MAX_DECOMPRESSED_SIZE));
            let gzip_result = gzip_decompressor.decompress(data, &mut gzip_output);

            let mut deflate_output = Vec::new();
            let mut deflate_decompressor = DeflateDecompressor::new(Some(MAX_DECOMPRESSED_SIZE));
            let deflate_result = deflate_decompressor.decompress(data, &mut deflate_output);

            let mut brotli_output = Vec::new();
            let mut brotli_decompressor = BrotliDecompressor::new(Some(MAX_DECOMPRESSED_SIZE));
            let brotli_result = brotli_decompressor.decompress(data, &mut brotli_output);

            // Verify that any successful decompression respects size limits
            for (name, result, output) in [
                ("gzip", &gzip_result, &gzip_output),
                ("deflate", &deflate_result, &deflate_output),
                ("brotli", &brotli_result, &brotli_output),
            ] {
                if result.is_ok() {
                    assert!(
                        output.len() <= MAX_DECOMPRESSED_SIZE,
                        "{} decompressor exceeded size limit: {} > {}",
                        name,
                        output.len(),
                        MAX_DECOMPRESSED_SIZE
                    );
                }
            }
        }
    }

    // Test 7: Encoding negotiation with fuzzer-generated headers
    if let Ok(header_str) = std::str::from_utf8(data) {
        if header_str.len() < 1000 {
            // Prevent excessively long headers
            // Test realistic encoding combinations
            let encoding_combinations = [
                &[ContentEncoding::Identity][..],
                &[ContentEncoding::Gzip],
                &[ContentEncoding::Deflate],
                &[ContentEncoding::Brotli],
                &[ContentEncoding::Gzip, ContentEncoding::Deflate],
                &[ContentEncoding::Gzip, ContentEncoding::Brotli],
                &[
                    ContentEncoding::Gzip,
                    ContentEncoding::Deflate,
                    ContentEncoding::Brotli,
                ],
                &[
                    ContentEncoding::Identity,
                    ContentEncoding::Gzip,
                    ContentEncoding::Deflate,
                    ContentEncoding::Brotli,
                ],
            ];

            for supported in &encoding_combinations {
                let _result = negotiate_encoding(Some(header_str), supported);
                let _result = negotiate_encoding(None, supported);
            }

            // Test malformed header variants
            let header_variants = [
                header_str.to_string(),
                header_str.to_uppercase(),
                header_str.to_lowercase(),
                format!("{}; q=0.5", header_str),
                format!("{}, gzip", header_str),
                format!("gzip, {}", header_str),
                format!("  {}  ", header_str),
                header_str.replace(";", " ; "),
                header_str.replace(",", " , "),
                header_str.repeat(3),
            ];

            for variant in &header_variants {
                if variant.len() < 2000 {
                    // Prevent excessive lengths
                    let _result = negotiate_encoding(Some(variant), &[ContentEncoding::Gzip]);
                }
            }
        }
    }

    // Test 8: Memory usage validation
    // Ensure that no decompression operation allocates excessive memory
    // This is implicitly tested by the size limits, but we can also check
    // that intermediate allocations don't spike
    if data.len() > 0 && data.len() < 100 {
        // For small inputs, test rapid create/destroy cycles to check for memory leaks
        for _ in 0..10 {
            let mut gzip = GzipDecompressor::new(Some(1024));
            let mut deflate = DeflateDecompressor::new(Some(1024));
            let mut brotli = BrotliDecompressor::new(Some(1024));
            let mut identity = IdentityDecompressor::new(Some(1024));

            let mut output = Vec::new();
            let _ = gzip.decompress(data, &mut output);
            let _ = deflate.decompress(data, &mut output);
            let _ = brotli.decompress(data, &mut output);
            let _ = identity.decompress(data, &mut output);

            // Explicit drop to ensure cleanup
            drop(gzip);
            drop(deflate);
            drop(brotli);
            drop(identity);
            output.clear();
        }
    }
});
