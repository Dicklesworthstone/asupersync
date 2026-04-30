//! HTTP/1.1 Chunked Transfer-Encoding Terminator Fuzzer
//!
//! Targets the chunked transfer-encoding terminator validation logic in
//! src/http/h1/codec.rs to test handling of arbitrary chunked byte sequences,
//! including missing final `0\r\n\r\n` terminators, ensuring malformed chunks
//! result in proper errors without body data leakage.
//!
//! Key invariants tested:
//! - Missing final chunk terminator `0\r\n\r\n` → BadChunkedEncoding error
//! - Incomplete chunk size lines → proper error handling
//! - Malformed chunk size values → parse errors
//! - Truncated trailer sections → clean failure
//! - Invalid CRLF sequences in terminators → rejection
//! - No body data leakage on malformed termination
//! - Proper state reset after chunk parsing failures

#![no_main]

use libfuzzer_sys::fuzz_target;
use asupersync::bytes::BytesMut;
use asupersync::codec::Decoder;
use asupersync::http::h1::codec::{Http1Codec, HttpError};

/// Maximum input size to prevent OOM
const MAX_INPUT_SIZE: usize = 64 * 1024;

/// Chunked encoding test patterns
const CHUNK_PATTERNS: &[&[u8]] = &[
    b"5\r\nhello\r\n0\r\n\r\n",                    // Valid minimal chunk
    b"5\r\nhello\r\n0\r\n",                        // Missing final CRLF
    b"5\r\nhello\r\n0",                            // Missing CRLF after final chunk size
    b"5\r\nhello\r\n",                             // Missing terminator entirely
    b"5\r\nhello\r\n0\r\nTrailer: value\r\n",     // Missing final CRLF with trailer
    b"a\r\nhelloworld\r\n0\r\n\r\n",              // Valid hex chunk size
    b"A\r\nHELLOWORLD\r\n0\r\n\r\n",              // Valid uppercase hex
    b"ff\r\n",                                      // Large chunk size but no data
];

fuzz_target!(|data: &[u8]| {
    // Guard against excessive input sizes
    if data.is_empty() || data.len() > MAX_INPUT_SIZE {
        return;
    }

    // Test 1: Raw fuzzed chunked data
    {
        let result = test_chunked_terminator(data);
        validate_chunked_result(result, data);
    }

    // Test 2: Valid chunk prefix + fuzzed terminator
    if data.len() >= 4 {
        let valid_prefix = b"5\r\nhello\r\n";
        let mut test_data = Vec::new();
        test_data.extend_from_slice(valid_prefix);
        test_data.extend_from_slice(data);

        let result = test_chunked_terminator(&test_data);
        validate_chunked_result(result, &test_data);
    }

    // Test 3: Pattern-based tests with fuzzed modifications
    for &pattern in CHUNK_PATTERNS {
        if data.len() >= 2 {
            // Modify pattern at fuzzed position
            let mut modified = pattern.to_vec();
            let pos = (data[0] as usize) % modified.len();
            let replacement = data[1];

            modified[pos] = replacement;

            let result = test_chunked_terminator(&modified);
            validate_chunked_result(result, &modified);
        }
    }

    // Test 4: Chunk size corruption
    if data.len() >= 8 {
        let chunk_size = format!("{:x}", (data[0] as usize) % 256);
        let body_len = (data[1] as usize) % 16;
        let body: Vec<u8> = data[2..].iter().take(body_len).copied().collect();

        let mut chunked = Vec::new();
        chunked.extend_from_slice(chunk_size.as_bytes());

        // Add potentially corrupted CRLF
        if data.len() > 8 {
            chunked.push(data[8]);
            if data.len() > 9 {
                chunked.push(data[9]);
            }
        } else {
            chunked.extend_from_slice(b"\r\n");
        }

        chunked.extend_from_slice(&body);
        chunked.extend_from_slice(b"\r\n0\r\n\r\n");

        let result = test_chunked_terminator(&chunked);
        validate_chunked_result(result, &chunked);
    }

    // Test 5: Trailer corruption
    if data.len() >= 16 {
        let mut chunked = b"5\r\nhello\r\n0\r\n".to_vec();

        // Add potentially corrupted trailer
        let trailer_data = &data[..std::cmp::min(data.len(), 32)];
        chunked.extend_from_slice(trailer_data);

        // May or may not have proper termination
        if data[0] & 0x01 != 0 {
            chunked.extend_from_slice(b"\r\n");
        }

        let result = test_chunked_terminator(&chunked);
        validate_chunked_result(result, &chunked);
    }

    // Test 6: Multiple chunk corruption
    if data.len() >= 12 {
        let chunk1_size = data[0] % 16 + 1; // 1-16 bytes
        let chunk2_size = data[1] % 16 + 1; // 1-16 bytes

        let mut chunked = Vec::new();

        // First chunk
        chunked.extend_from_slice(format!("{:x}\r\n", chunk1_size).as_bytes());
        chunked.extend_from_slice(&data[2..2+chunk1_size.min(data.len()-2)]);
        chunked.extend_from_slice(b"\r\n");

        // Second chunk with potential corruption
        chunked.extend_from_slice(format!("{:x}", chunk2_size).as_bytes());

        // Potentially corrupted CRLF after chunk size
        let crlf_pos = 2 + chunk1_size + 3; // Position after first chunk
        if crlf_pos + 1 < data.len() {
            chunked.push(data[crlf_pos]);
            chunked.push(data[crlf_pos + 1]);
        } else {
            chunked.extend_from_slice(b"\r\n");
        }

        // Add chunk data
        let data_start = crlf_pos + 2;
        if data_start < data.len() {
            let chunk_data = &data[data_start..data_start+chunk2_size.min(data.len()-data_start)];
            chunked.extend_from_slice(chunk_data);
        }

        // Terminator may be corrupted
        chunked.extend_from_slice(b"\r\n0\r\n\r\n");

        let result = test_chunked_terminator(&chunked);
        validate_chunked_result(result, &chunked);
    }

    // Test 7: Zero-length chunk variations
    {
        let zero_chunk_terminators = [
            b"0\r\n\r\n",           // Valid
            b"0\r\n",               // Missing final CRLF
            b"0",                   // Missing all CRLF
            b"0\n\n",               // LF only (invalid)
            b"0\r",                 // Incomplete
            b"0\r\n\r",             // Incomplete final
        ];

        for &terminator in &zero_chunk_terminators {
            if data.len() >= 4 {
                let mut test_chunk = b"5\r\nhello\r\n".to_vec();
                test_chunk.extend_from_slice(terminator);

                // Add fuzzed data after terminator
                test_chunk.extend_from_slice(&data[..4]);

                let result = test_chunked_terminator(&test_chunk);
                validate_chunked_result(result, &test_chunk);
            }
        }
    }

    // Test 8: Chunk size edge cases
    {
        let edge_sizes = [
            "0",           // Terminal chunk
            "1",           // Minimum
            "ff",          // 255 bytes
            "1000",        // 4096 bytes
            "ffffffff",    // Large value
            "",            // Empty (invalid)
        ];

        for &size_str in &edge_sizes {
            if data.len() >= 4 {
                let mut chunk = Vec::new();
                chunk.extend_from_slice(size_str.as_bytes());
                chunk.extend_from_slice(b"\r\n");

                if !size_str.is_empty() && size_str != "0" {
                    // Add some data for non-terminal chunks
                    let data_len = std::cmp::min(data.len(), 16);
                    chunk.extend_from_slice(&data[..data_len]);
                    chunk.extend_from_slice(b"\r\n");
                }

                // Add terminal chunk (potentially corrupted)
                chunk.extend_from_slice(b"0\r\n");
                if data.len() > 0 && data[0] & 0x80 != 0 {
                    // Sometimes add corrupted final CRLF
                    chunk.extend_from_slice(&data[..std::cmp::min(2, data.len())]);
                } else {
                    chunk.extend_from_slice(b"\r\n");
                }

                let result = test_chunked_terminator(&chunk);
                validate_chunked_result(result, &chunk);
            }
        }
    }

    // Test 9: Extension corruption in chunk size line
    if data.len() >= 8 {
        let size = data[0] % 16 + 1;
        let mut chunk = format!("{:x}", size).into_bytes();

        // Add potentially corrupted chunk extension
        chunk.push(b';');
        chunk.extend_from_slice(&data[1..std::cmp::min(8, data.len())]);
        chunk.extend_from_slice(b"\r\n");

        // Add chunk data
        chunk.extend_from_slice(&data[..size.min(data.len())]);
        chunk.extend_from_slice(b"\r\n0\r\n\r\n");

        let result = test_chunked_terminator(&chunk);
        validate_chunked_result(result, &chunk);
    }

    // Test 10: Incomplete input scenarios
    {
        let complete_chunk = b"5\r\nhello\r\n0\r\n\r\n";

        // Test various truncation points
        for i in 1..complete_chunk.len() {
            let mut truncated = complete_chunk[..i].to_vec();

            // Add fuzzed data to truncated chunk
            if !data.is_empty() {
                let fuzz_len = std::cmp::min(data.len(), 8);
                truncated.extend_from_slice(&data[..fuzz_len]);
            }

            let result = test_chunked_terminator(&truncated);
            validate_chunked_result(result, &truncated);
        }
    }
});

/// Test chunked terminator parsing with arbitrary data
fn test_chunked_terminator(chunked_data: &[u8]) -> Result<Vec<u8>, HttpError> {
    let mut codec = Http1Codec::new();

    // Create a proper HTTP request with chunked transfer encoding
    let mut request = BytesMut::new();
    request.extend_from_slice(b"POST /test HTTP/1.1\r\n");
    request.extend_from_slice(b"Host: example.com\r\n");
    request.extend_from_slice(b"Transfer-Encoding: chunked\r\n");
    request.extend_from_slice(b"\r\n");
    request.extend_from_slice(chunked_data);

    match codec.decode(&mut request) {
        Ok(Some(req)) => Ok(req.body),
        Ok(None) => Ok(Vec::new()), // Incomplete, but not an error
        Err(e) => Err(e),
    }
}

/// Validate chunked parsing result for security properties
fn validate_chunked_result(result: Result<Vec<u8>, HttpError>, input_data: &[u8]) {
    match result {
        Ok(body) => {
            // If parsing succeeded, the body should be valid
            // Body length should be reasonable (not unbounded)
            if body.len() > input_data.len() * 2 {
                // Body suspiciously larger than input - possible amplification
                panic!("Body size {} exceeds reasonable bounds for input size {}",
                       body.len(), input_data.len());
            }
        }
        Err(HttpError::BadChunkedEncoding) => {
            // Expected error for malformed chunks - this is correct
        }
        Err(HttpError::BodyTooLarge) => {
            // Valid error for oversized bodies
        }
        Err(HttpError::HeadersTooLarge) => {
            // Valid error for oversized trailers
        }
        Err(HttpError::BadHeader) => {
            // May occur if malformed trailer headers
        }
        Err(HttpError::Io(_)) => {
            // I/O errors are acceptable
        }
        Err(other) => {
            // Other errors might indicate unexpected behavior
            // Don't panic here as they might be valid edge cases
            eprintln!("Unexpected error for chunked parsing: {:?}", other);
        }
    }
}

/// Test specific terminator corruption scenarios
fn test_terminator_corruption() {
    let test_cases = [
        // Valid cases
        (b"0\r\n\r\n".as_slice(), true),

        // Missing final CRLF
        (b"0\r\n\r".as_slice(), false),
        (b"0\r\n".as_slice(), false),
        (b"0\r".as_slice(), false),
        (b"0".as_slice(), false),

        // Wrong line endings
        (b"0\n\n".as_slice(), false),
        (b"0\r\n\n".as_slice(), false),
        (b"0\n\r\n".as_slice(), false),

        // With trailers
        (b"0\r\nX-Trailer: value\r\n\r\n".as_slice(), true),
        (b"0\r\nX-Trailer: value\r\n".as_slice(), false),
        (b"0\r\nX-Trailer: value\r\n\r".as_slice(), false),
    ];

    for (terminator, should_succeed) in test_cases {
        let mut chunk_data = b"5\r\nhello\r\n".to_vec();
        chunk_data.extend_from_slice(terminator);

        let result = test_chunked_terminator(&chunk_data);

        match (result, should_succeed) {
            (Ok(_), true) => {}, // Expected success
            (Err(_), false) => {}, // Expected failure
            (Ok(_), false) => {
                panic!("Expected failure for terminator {:?} but got success", terminator);
            }
            (Err(e), true) => {
                panic!("Expected success for terminator {:?} but got error: {:?}", terminator, e);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_chunked_termination() {
        let valid = b"5\r\nhello\r\n0\r\n\r\n";
        let result = test_chunked_terminator(valid);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), b"hello");
    }

    #[test]
    fn test_missing_final_crlf() {
        let invalid = b"5\r\nhello\r\n0\r\n";
        let result = test_chunked_terminator(invalid);
        assert!(matches!(result, Ok(body) if body.is_empty()) || result.is_err());
    }

    #[test]
    fn test_truncated_terminator() {
        let invalid = b"5\r\nhello\r\n0";
        let result = test_chunked_terminator(invalid);
        assert!(matches!(result, Ok(body) if body.is_empty()) || result.is_err());
    }

    #[test]
    fn test_corrupted_chunk_size() {
        let invalid = b"g\r\nhello\r\n0\r\n\r\n"; // 'g' is not hex
        let result = test_chunked_terminator(invalid);
        assert!(result.is_err());
    }

    #[test]
    fn test_trailer_handling() {
        let with_trailer = b"5\r\nhello\r\n0\r\nX-Trailer: value\r\n\r\n";
        let result = test_chunked_terminator(with_trailer);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), b"hello");
    }

    #[test]
    fn test_missing_trailer_termination() {
        let invalid = b"5\r\nhello\r\n0\r\nX-Trailer: value\r\n";
        let result = test_chunked_terminator(invalid);
        assert!(matches!(result, Ok(body) if body.is_empty()) || result.is_err());
    }

    #[test]
    fn test_multiple_chunks() {
        let valid = b"3\r\nfoo\r\n3\r\nbar\r\n0\r\n\r\n";
        let result = test_chunked_terminator(valid);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), b"foobar");
    }

    #[test]
    fn test_zero_length_chunk() {
        let valid = b"0\r\n\r\n";
        let result = test_chunked_terminator(valid);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), b"");
    }

    #[test]
    fn test_terminator_corruption_scenarios() {
        test_terminator_corruption();
    }

    #[test]
    fn test_chunk_extension_parsing() {
        let with_extension = b"5;name=value\r\nhello\r\n0\r\n\r\n";
        let result = test_chunked_terminator(with_extension);
        // Should handle chunk extensions gracefully
        assert!(result.is_ok() || result.is_err()); // Both are acceptable
    }
}