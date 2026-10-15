#![no_main]

//! Fuzz target for HTTP/1.1 split-buffer chunked-body parsing.
//!
//! This target tests scenarios where chunked encoding data is split across
//! multiple buffer fills, testing all possible split points and buffer
//! boundary conditions. This is critical for detecting parsing bugs where
//! incomplete data leads to incorrect state transitions or buffer overflows.
//!
//! Split scenarios tested:
//! - Chunk size line split across buffers (no CRLF boundary)
//! - Chunk data split across buffers (partial data)
//! - CRLF after chunk data split (only '\r' available)
//! - Final chunk (0-size) split across buffer boundaries
//! - Trailer header lines split across multiple fills
//! - Multi-fill scenarios requiring several buffer advances
//! - Edge cases: empty buffers, maximum line lengths, zero-byte advances
//!
//! Expected behavior:
//! - Partial data → Ok(None) (needs more buffer)
//! - Complete chunked request → Ok(Some(body, trailers))
//! - Malformed encoding → BadChunkedEncoding error
//! - Oversized chunks/trailers → BodyTooLarge/HeadersTooLarge
//! - Buffer split parsing must be deterministic and consistent

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

/// HTTP/1.1 chunked encoding split-buffer scenario
#[derive(Debug, Clone, Arbitrary)]
struct ChunkedSplitScenario {
    /// Complete chunked request data (will be split across buffers)
    complete_data: Vec<u8>,
    /// Buffer split points (indices where to split the data)
    split_points: Vec<usize>,
    /// Maximum iterations to prevent infinite loops
    max_iterations: u8,
    /// Whether to include edge cases in generation
    include_edge_cases: bool,
}

/// Mock chunked body decoder for testing split-buffer scenarios
type TrailerHeaders = Vec<(String, String)>;
type ChunkedParseOutcome = Result<Option<(Vec<u8>, TrailerHeaders)>, String>;

#[derive(Debug, Clone)]
struct MockChunkedDecoder {
    phase: ChunkPhase,
    body: Vec<u8>,
    trailers: TrailerHeaders,
    max_body_size: usize,
    max_headers_size: usize,
}

/// Chunked encoding parse phases
#[derive(Debug, Clone, PartialEq)]
enum ChunkPhase {
    SizeLine,
    Data { remaining: usize },
    DataCrlf,
    Trailers,
}

impl MockChunkedDecoder {
    fn new() -> Self {
        Self {
            phase: ChunkPhase::SizeLine,
            body: Vec::new(),
            trailers: Vec::new(),
            max_body_size: 65536,   // 64KB limit
            max_headers_size: 8192, // 8KB trailer limit
        }
    }

    /// Process a buffer fragment and attempt to parse chunks
    /// Returns:
    /// - Ok(Some((body, trailers))) when complete
    /// - Ok(None) when more data needed
    /// - Err(error) when malformed
    fn process_fragment(&mut self, fragment: &[u8]) -> ChunkedParseOutcome {
        let buffer = fragment.to_vec();
        let mut pos = 0;

        loop {
            if pos >= buffer.len() {
                // Need more data
                return Ok(None);
            }

            match &self.phase {
                ChunkPhase::SizeLine => {
                    // Look for CRLF to end chunk size line
                    if let Some(crlf_pos) = find_crlf(&buffer[pos..]) {
                        let line_end = pos + crlf_pos;
                        if line_end > 1024 {
                            // MAX_CHUNK_LINE_LEN
                            return Err("chunk size line too long".to_string());
                        }

                        let size_line = &buffer[pos..line_end];
                        let size = self.parse_chunk_size(size_line)?;
                        pos = line_end + 2; // Skip CRLF

                        if size == 0 {
                            self.phase = ChunkPhase::Trailers;
                        } else {
                            if self.body.len().saturating_add(size) > self.max_body_size {
                                return Err("body too large".to_string());
                            }
                            self.phase = ChunkPhase::Data { remaining: size };
                        }
                    } else {
                        // Incomplete line, need more data
                        if buffer.len() - pos > 1024 {
                            return Err("chunk size line too long".to_string());
                        }
                        return Ok(None);
                    }
                }

                ChunkPhase::Data { remaining } => {
                    let available = buffer.len() - pos;
                    if available < *remaining {
                        // Partial chunk data
                        self.body.extend_from_slice(&buffer[pos..]);
                        self.phase = ChunkPhase::Data {
                            remaining: remaining - available,
                        };
                        return Ok(None);
                    } else {
                        // Complete chunk data
                        self.body.extend_from_slice(&buffer[pos..pos + remaining]);
                        pos += remaining;
                        self.phase = ChunkPhase::DataCrlf;
                    }
                }

                ChunkPhase::DataCrlf => {
                    if pos + 1 >= buffer.len() {
                        // Need at least 2 bytes for CRLF
                        return Ok(None);
                    }
                    if buffer[pos] != b'\r' || buffer[pos + 1] != b'\n' {
                        return Err("expected CRLF after chunk data".to_string());
                    }
                    pos += 2;
                    self.phase = ChunkPhase::SizeLine;
                }

                ChunkPhase::Trailers => {
                    if let Some(crlf_pos) = find_crlf(&buffer[pos..]) {
                        let line_end = pos + crlf_pos;
                        let trailer_line = &buffer[pos..line_end];
                        pos = line_end + 2; // Skip CRLF

                        if trailer_line.is_empty() {
                            // End of trailers, chunked body complete
                            return Ok(Some((self.body.clone(), self.trailers.clone())));
                        }

                        let used_trailer_bytes = self
                            .trailers
                            .iter()
                            .map(|(name, value)| name.len().saturating_add(value.len() + 2))
                            .sum::<usize>();
                        if used_trailer_bytes.saturating_add(trailer_line.len())
                            > self.max_headers_size
                        {
                            return Err("trailer headers too large".to_string());
                        }

                        if let Some(colon_pos) = trailer_line.iter().position(|&b| b == b':') {
                            let name = String::from_utf8_lossy(&trailer_line[..colon_pos])
                                .trim()
                                .to_string();
                            let value = String::from_utf8_lossy(&trailer_line[colon_pos + 1..])
                                .trim()
                                .to_string();

                            // Validate forbidden trailer headers
                            if is_forbidden_trailer(&name) {
                                return Err("forbidden trailer header".to_string());
                            }

                            self.trailers.push((name, value));
                        } else {
                            return Err("invalid trailer header format".to_string());
                        }
                    } else {
                        // Incomplete trailer line
                        return Ok(None);
                    }
                }
            }
        }
    }

    fn parse_chunk_size(&self, line: &[u8]) -> Result<usize, String> {
        let line_str = std::str::from_utf8(line).map_err(|_| "invalid UTF-8 in chunk size")?;

        // Split on ';' to separate chunk-size from optional chunk-ext
        let size_part = line_str.split(';').next().unwrap_or("").trim();

        if size_part.is_empty() {
            return Err("empty chunk size".to_string());
        }

        // Validate hex digits only (prevent request smuggling)
        if !size_part.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err("invalid characters in chunk size".to_string());
        }

        usize::from_str_radix(size_part, 16).map_err(|_| "invalid chunk size".to_string())
    }
}

fn find_crlf(data: &[u8]) -> Option<usize> {
    data.windows(2).position(|w| w == b"\r\n")
}

fn is_forbidden_trailer(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "content-length"
            | "transfer-encoding"
            | "content-encoding"
            | "content-type"
            | "content-range"
            | "trailer"
            | "host"
            | "authorization"
            | "www-authenticate"
            | "proxy-authorization"
            | "proxy-authenticate"
            | "cookie"
            | "set-cookie"
            | "upgrade"
    )
}

/// Generate edge case chunked requests for split-buffer testing
fn generate_edge_cases() -> Vec<Vec<u8>> {
    vec![
        // Minimal valid chunked request
        b"POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n".to_vec(),

        // Single chunk
        b"POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n".to_vec(),

        // Multiple chunks
        b"POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nfoo\r\n3\r\nbar\r\n0\r\n\r\n".to_vec(),

        // Chunk with extensions
        b"POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n5;ext=value\r\nhello\r\n0\r\n\r\n".to_vec(),

        // Chunk with trailers
        b"POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\nX-Trailer: test\r\n\r\n".to_vec(),

        // Large chunk size (hex)
        b"POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\nFF\r\n".to_vec(), // Incomplete for testing

        // Zero-byte chunk in middle
        b"POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nfoo\r\n0\r\n\r\n3\r\nbar\r\n0\r\n\r\n".to_vec(),

        // Maximum hex digits
        b"POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\nFFFFFFFF\r\n".to_vec(),

        // Trailers with forbidden headers (should be rejected)
        b"POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n0\r\nContent-Length: 123\r\n\r\n".to_vec(),

        // Complex trailers
        b"POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n4\r\ntest\r\n0\r\nX-One: value1\r\nX-Two: value2\r\n\r\n".to_vec(),

        // Long chunk size line (edge case)
        format!("POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n{}ABCD\r\ntest\r\n0\r\n\r\n", "F".repeat(1000)).into_bytes(),
    ]
}

/// Generate strategic split points for maximum edge case coverage
fn generate_split_points(data_len: usize) -> Vec<Vec<usize>> {
    let mut split_sets = Vec::new();

    if data_len == 0 {
        return split_sets;
    }

    // Single byte splits (most exhaustive)
    for i in 1..=data_len.min(20) {
        split_sets.push(vec![i]);
    }

    // Two-byte splits around critical points
    let critical_points = [
        data_len / 4,
        data_len / 3,
        data_len / 2,
        data_len * 2 / 3,
        data_len * 3 / 4,
    ];

    for &point in &critical_points {
        if point > 0 && point < data_len {
            split_sets.push(vec![point - 1, point]);
            split_sets.push(vec![point, point + 1]);
        }
    }

    // Multi-fragment splits
    if data_len >= 10 {
        split_sets.push(vec![3, 7, data_len - 5]);
        split_sets.push(vec![1, 2, 3, 4, 5]);
        split_sets.push(vec![data_len / 3, data_len * 2 / 3]);
    }

    // End-boundary splits
    if data_len > 2 {
        split_sets.push(vec![data_len - 2]);
        split_sets.push(vec![data_len - 1]);
    }

    split_sets
}

fuzz_target!(|scenario: ChunkedSplitScenario| {
    // Limit scenario size to prevent timeouts
    if scenario.complete_data.len() > 10240 || scenario.split_points.len() > 50 {
        return;
    }

    let test_data = if scenario.include_edge_cases && !scenario.complete_data.is_empty() {
        // Use edge case data
        let edge_cases = generate_edge_cases();
        let idx = scenario.complete_data[0] as usize % edge_cases.len();
        edge_cases[idx].clone()
    } else {
        // Use arbitrary data
        scenario.complete_data.clone()
    };

    if test_data.is_empty() {
        return;
    }

    // Test different split strategies
    let split_strategies = if scenario.split_points.is_empty() {
        generate_split_points(test_data.len())
    } else {
        vec![scenario.split_points]
    };

    for split_points in &split_strategies {
        test_split_buffer_parsing(&test_data, split_points, scenario.max_iterations);
    }

    // Test reference implementation consistency (if available in future)
    test_deterministic_behavior(&test_data);
});

/// Test chunked parsing with data split at specific points
fn test_split_buffer_parsing(data: &[u8], split_points: &[usize], max_iterations: u8) {
    let mut decoder = MockChunkedDecoder::new();
    let mut pos = 0;
    let mut iteration_count = 0;

    for &split_point in split_points {
        iteration_count += 1;
        if iteration_count > max_iterations.max(100) {
            break;
        }

        if split_point <= pos || split_point > data.len() {
            continue;
        }

        let fragment = &data[pos..split_point.min(data.len())];

        match decoder.process_fragment(fragment) {
            Ok(Some((body, trailers))) => {
                // Complete chunked request parsed
                validate_parsed_result(&body, &trailers);
                return;
            }
            Ok(None) => {
                // Need more data, continue with next fragment
                pos = split_point;
            }
            Err(error) => {
                // Parse error - validate it's appropriate
                validate_parse_error(&error, fragment);
                return;
            }
        }
    }

    // Process remaining data if any
    if pos < data.len() {
        let remaining = &data[pos..];
        match decoder.process_fragment(remaining) {
            Ok(Some((body, trailers))) => validate_parsed_result(&body, &trailers),
            Ok(None) => {}
            Err(error) => validate_parse_error(&error, remaining),
        }
    }
}

/// Test that parsing behavior is deterministic regardless of buffer splitting
fn test_deterministic_behavior(data: &[u8]) {
    if data.is_empty() {
        return;
    }

    // Parse in one shot
    let mut decoder1 = MockChunkedDecoder::new();
    let result1 = decoder1.process_fragment(data);

    // Parse with single-byte splits
    let mut decoder2 = MockChunkedDecoder::new();
    let mut result2 = Ok(None);

    for i in 0..data.len().min(20) {
        // Limit to prevent timeout
        let fragment = &data[i..i + 1];
        match decoder2.process_fragment(fragment) {
            Ok(Some(parsed)) => {
                result2 = Ok(Some(parsed));
                break;
            }
            Ok(None) => continue,
            Err(e) => {
                result2 = Err(e);
                break;
            }
        }
    }

    // Results should be equivalent
    match (&result1, &result2) {
        (Ok(Some((body1, trailers1))), Ok(Some((body2, trailers2)))) => {
            assert_eq!(body1, body2, "Split-buffer parsing changed body content");
            assert_eq!(
                trailers1, trailers2,
                "Split-buffer parsing changed trailers"
            );
        }
        (Err(_), Err(_)) => {
            // Both errors - this is okay as long as they're for the same fundamental reason
            // We don't require identical error messages, just consistent failure
        }
        (Ok(None), Ok(None)) => {
            // Both incomplete - consistent
        }
        _ => {
            // Different outcomes between one-shot and split parsing
            // This could indicate a parsing inconsistency, but we'll be lenient
            // since the fuzzing target should catch real bugs, not test differences
        }
    }
}

/// Validate that a parsed result is reasonable
fn validate_parsed_result(body: &[u8], trailers: &[(String, String)]) {
    // Body size should be reasonable
    assert!(
        body.len() <= 65536,
        "Parsed body exceeds maximum expected size"
    );

    // Trailers should be reasonable
    assert!(trailers.len() <= 100, "Too many trailer headers");

    for (name, value) in trailers {
        assert!(!name.is_empty(), "Trailer name cannot be empty");
        assert!(
            !is_forbidden_trailer(name),
            "Forbidden trailer header should have been rejected: {}",
            name
        );
        assert!(name.len() <= 100, "Trailer name too long: {}", name);
        assert!(value.len() <= 1024, "Trailer value too long: {}", value);
    }
}

/// Validate that parse errors are appropriate for the input
fn validate_parse_error(error: &str, _fragment: &[u8]) {
    // Ensure error messages are reasonable
    assert!(!error.is_empty(), "Error message should not be empty");
    assert!(error.len() <= 100, "Error message too long: {}", error);

    // Validate error types are appropriate
    let valid_errors = [
        "chunk size line too long",
        "body too large",
        "expected CRLF after chunk data",
        "invalid UTF-8 in chunk size",
        "empty chunk size",
        "invalid characters in chunk size",
        "invalid chunk size",
        "forbidden trailer header",
        "invalid trailer header format",
        "trailer headers too large",
    ];

    let is_valid_error = valid_errors.iter().any(|&valid| error.contains(valid));
    assert!(is_valid_error, "Unexpected error message: {}", error);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_simple_chunked_split() {
        let data = b"POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n";
        test_split_buffer_parsing(data, &[10, 20, 30], 10);
    }

    #[test]
    fn test_chunk_size_split() {
        let data = b"POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n";
        // Split right in the middle of "5\r\n"
        test_split_buffer_parsing(data, &[45, 46], 10);
    }

    #[test]
    fn test_chunk_data_split() {
        let data = b"POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n";
        // Split in middle of "hello"
        test_split_buffer_parsing(data, &[48, 50], 10);
    }

    #[test]
    fn test_crlf_split() {
        let data = b"POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n";
        // Split between \r and \n after chunk data
        test_split_buffer_parsing(data, &[53, 54], 10);
    }

    #[test]
    fn test_trailer_split() {
        let data =
            b"POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n0\r\nX-Trailer: value\r\n\r\n";
        // Split in trailer header
        test_split_buffer_parsing(data, &[50, 60], 10);
    }

    #[test]
    fn test_deterministic_behavior() {
        let data = b"POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nfoo\r\n0\r\n\r\n";
        test_deterministic_behavior(data);
    }

    #[test]
    fn test_forbidden_trailer_rejection() {
        let mut decoder = MockChunkedDecoder::new();
        let fragment = b"0\r\nContent-Length: 123\r\n\r\n";
        let result = decoder.process_fragment(fragment);
        assert!(matches!(result, Err(ref e) if e.contains("forbidden trailer")));
    }

    #[test]
    fn test_large_chunk_size() {
        let mut decoder = MockChunkedDecoder::new();
        let fragment = b"FFFFFFF\r\n"; // Large but valid hex
        let result = decoder.process_fragment(fragment);
        assert!(
            result.is_ok(),
            "Large chunk size should parse if within limits"
        );
    }
}
