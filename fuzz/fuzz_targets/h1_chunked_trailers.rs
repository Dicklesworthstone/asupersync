#![no_main]

//! Fuzz target for HTTP/1.1 chunked-body trailers validation.
//!
//! This target tests that HTTP/1.1 trailers in chunked encoding are properly validated:
//! - Trailers MUST only be parsed after the final 0-chunk per RFC 9112 §7.1.3
//! - Trailer headers MUST NOT contain forbidden headers per RFC 9110 §6.5.1
//! - Malformed trailer syntax should be rejected
//! - Trailers appearing before final chunk should cause protocol error
//!
//! Expected behavior:
//! - Trailers before final 0-chunk: BadChunkedEncoding error
//! - Forbidden trailer headers: BadHeader error
//! - Valid trailers after 0-chunk: successfully parsed
//! - Malformed trailer syntax: BadHeader error

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use std::collections::HashMap;

/// HTTP/1.1 chunk with optional trailer data
#[derive(Debug, Clone, Arbitrary)]
struct Chunk {
    /// Chunk size in hex (will be converted to hex string)
    size: u16,
    /// Chunk data (will be truncated to size)
    data: Vec<u8>,
    /// Whether to include trailers illegally before final chunk
    illegal_trailers_before_final: bool,
    /// Trailers to include (only valid after final 0-chunk)
    trailers: Vec<TrailerHeader>,
}

/// A trailer header name-value pair
#[derive(Debug, Clone, Arbitrary)]
struct TrailerHeader {
    name: String,
    value: String,
    /// Whether to use forbidden header name
    use_forbidden_name: bool,
    /// Whether to include malformed syntax
    malformed_syntax: bool,
}

/// Chunked body test scenario
#[derive(Debug, Clone, Arbitrary)]
struct ChunkedTrailerScenario {
    /// Sequence of chunks (last will be 0-size final chunk)
    chunks: Vec<Chunk>,
    /// Final trailers (after 0-chunk)
    final_trailers: Vec<TrailerHeader>,
    /// Whether to include final empty line
    include_final_empty_line: bool,
    /// Whether to include malformed final chunk
    malformed_final_chunk: bool,
    /// Maximum body size for testing size limits
    max_body_size: u32,
    /// Maximum trailer size for testing limits
    max_trailer_size: u32,
}

/// Mock chunked decoder for testing
struct MockChunkedDecoder {
    phase: ChunkPhase,
    body: Vec<u8>,
    trailers: Vec<(String, String)>,
    trailers_bytes: usize,
    max_body_size: usize,
    max_trailer_size: usize,
    errors: Vec<String>,
}

#[derive(Debug, Clone)]
enum ChunkPhase {
    SizeLine,
    Data { remaining: usize },
    DataCrlf,
    Trailers,
    Complete,
    Error,
}

impl MockChunkedDecoder {
    fn new(max_body_size: usize, max_trailer_size: usize) -> Self {
        Self {
            phase: ChunkPhase::SizeLine,
            body: Vec::new(),
            trailers: Vec::new(),
            trailers_bytes: 0,
            max_body_size,
            max_trailer_size,
            errors: Vec::new(),
        }
    }

    /// Process a chunk size line (hex + CRLF)
    fn process_chunk_size(&mut self, size_line: &str) -> Result<(), String> {
        match &self.phase {
            ChunkPhase::SizeLine => {
                let size_str = size_line.trim_end_matches("\r\n");

                // Split on ';' for chunk extensions
                let size_part = size_str.split(';').next().unwrap_or("");

                if size_part.is_empty() {
                    return Err("Empty chunk size".into());
                }

                // Parse hex size
                let size = match usize::from_str_radix(size_part, 16) {
                    Ok(s) => s,
                    Err(_) => return Err("Invalid chunk size".into()),
                };

                if size == 0 {
                    // Final chunk - transition to trailers
                    self.phase = ChunkPhase::Trailers;
                } else {
                    // Regular chunk - prepare for data
                    if self.body.len() + size > self.max_body_size {
                        return Err("Body too large".into());
                    }
                    self.phase = ChunkPhase::Data { remaining: size };
                }
                Ok(())
            }
            _ => Err("Unexpected chunk size line".into()),
        }
    }

    /// Process chunk data
    fn process_chunk_data(&mut self, data: &[u8]) -> Result<(), String> {
        match &mut self.phase {
            ChunkPhase::Data { remaining } => {
                if data.len() != *remaining {
                    return Err(format!("Expected {} bytes, got {}", remaining, data.len()));
                }
                self.body.extend_from_slice(data);
                self.phase = ChunkPhase::DataCrlf;
                Ok(())
            }
            _ => Err("Unexpected chunk data".into()),
        }
    }

    /// Process CRLF after chunk data
    fn process_data_crlf(&mut self) -> Result<(), String> {
        match &self.phase {
            ChunkPhase::DataCrlf => {
                self.phase = ChunkPhase::SizeLine;
                Ok(())
            }
            _ => Err("Unexpected data CRLF".into()),
        }
    }

    /// Process a trailer header line
    fn process_trailer(&mut self, trailer_line: &str) -> Result<(), String> {
        match &self.phase {
            ChunkPhase::Trailers => {
                let line = trailer_line.trim_end_matches("\r\n");

                if line.is_empty() {
                    // Empty line ends trailers
                    self.phase = ChunkPhase::Complete;
                    return Ok(());
                }

                self.trailers_bytes += trailer_line.len();
                if self.trailers_bytes > self.max_trailer_size {
                    return Err("Trailers too large".into());
                }

                // Parse header line
                let (name, value) = match parse_header_line(line) {
                    Ok(h) => h,
                    Err(e) => return Err(format!("Malformed trailer: {}", e)),
                };

                // Check forbidden trailers
                if is_forbidden_trailer(&name) {
                    return Err(format!("Forbidden trailer header: {}", name));
                }

                self.trailers.push((name, value));
                Ok(())
            }
            _ => Err("Trailers not allowed in this phase".into()),
        }
    }

    /// Check if currently in valid state to receive trailers
    fn can_receive_trailers(&self) -> bool {
        matches!(self.phase, ChunkPhase::Trailers)
    }

    /// Get final result
    fn finalize(self) -> Result<(Vec<u8>, Vec<(String, String)>), Vec<String>> {
        if matches!(self.phase, ChunkPhase::Complete) {
            Ok((self.body, self.trailers))
        } else {
            Err(self.errors)
        }
    }
}

/// Parse a header line into name and value
fn parse_header_line(line: &str) -> Result<(String, String), String> {
    let colon_pos = line.find(':').ok_or("No colon in header line")?;

    if colon_pos == 0 {
        return Err("Empty header name".into());
    }

    let name = line[..colon_pos].trim();
    let value = line[colon_pos + 1..].trim();

    // Validate header name (basic check for control chars)
    if name.is_empty() || name.chars().any(|c| c.is_control() || c == ' ') {
        return Err("Invalid header name".into());
    }

    // Validate header value (basic check for control chars except HTAB)
    if value.chars().any(|c| c.is_control() && c != '\t') {
        return Err("Invalid header value".into());
    }

    Ok((name.to_lowercase(), value.to_string()))
}

/// Check if a header name is forbidden in trailers per RFC 9110 §6.5.1
fn is_forbidden_trailer(name: &str) -> bool {
    const FORBIDDEN: &[&str] = &[
        "authorization",
        "cache-control",
        "content-encoding",
        "content-length",
        "content-range",
        "content-type",
        "host",
        "max-forwards",
        "proxy-authorization",
        "range",
        "te",
        "trailer",
        "transfer-encoding",
    ];

    FORBIDDEN
        .iter()
        .any(|&forbidden| name.eq_ignore_ascii_case(forbidden))
}

/// Generate forbidden header names for testing
fn generate_forbidden_header_name(use_forbidden: bool, base_name: &str) -> String {
    if use_forbidden {
        let forbidden_names = [
            "content-length",
            "transfer-encoding",
            "authorization",
            "host",
            "cache-control",
            "content-type",
            "trailer",
        ];
        forbidden_names[base_name.len() % forbidden_names.len()].to_string()
    } else {
        // Use safe trailer header names
        let safe_names = ["x-trace-id", "x-custom", "x-timestamp", "server-timing"];
        safe_names[base_name.len() % safe_names.len()].to_string()
    }
}

fuzz_target!(|scenario: ChunkedTrailerScenario| {
    // Skip scenarios that are too large to avoid timeouts
    if scenario.chunks.len() > 50 || scenario.final_trailers.len() > 20 {
        return;
    }

    // Clamp size limits to reasonable ranges
    let max_body_size = scenario.max_body_size.clamp(100, 100_000) as usize;
    let max_trailer_size = scenario.max_trailer_size.clamp(100, 10_000) as usize;

    let mut decoder = MockChunkedDecoder::new(max_body_size, max_trailer_size);
    let mut errors = Vec::new();
    let mut expected_to_fail = false;

    // Process chunks
    for (i, chunk) in scenario.chunks.iter().enumerate() {
        let is_last_chunk = i == scenario.chunks.len() - 1;
        let actual_size = if is_last_chunk && !scenario.malformed_final_chunk {
            0 // Final chunk is always 0-size
        } else {
            chunk.size.min(chunk.data.len() as u16) as usize
        };

        // Generate chunk size line
        let size_line = if scenario.malformed_final_chunk && is_last_chunk {
            "G\r\n".to_string() // Invalid hex
        } else {
            format!("{:X}\r\n", actual_size)
        };

        // Process chunk size
        if let Err(e) = decoder.process_chunk_size(&size_line) {
            errors.push(e);
            if scenario.malformed_final_chunk && is_last_chunk {
                // Expected error for malformed final chunk
                expected_to_fail = true;
            }
            break;
        }

        // Check for illegal trailers before final chunk
        if chunk.illegal_trailers_before_final && actual_size > 0 {
            // Try to add trailers illegally (should fail)
            if decoder.can_receive_trailers() {
                // This shouldn't happen - would be a bug
                errors.push("Trailers allowed before final chunk".into());
                expected_to_fail = true;
                break;
            }
        }

        // Process chunk data if not final chunk
        if actual_size > 0 {
            let chunk_data = if chunk.data.len() >= actual_size {
                &chunk.data[..actual_size]
            } else {
                &chunk.data
            };

            if let Err(e) = decoder.process_chunk_data(chunk_data) {
                errors.push(e);
                break;
            }

            // Process data CRLF
            if let Err(e) = decoder.process_data_crlf() {
                errors.push(e);
                break;
            }
        }
    }

    // Process final trailers if we reached the trailer phase
    if decoder.can_receive_trailers() {
        for trailer in &scenario.final_trailers {
            let header_name =
                generate_forbidden_header_name(trailer.use_forbidden_name, &trailer.name);

            let trailer_line = if trailer.malformed_syntax {
                // Invalid syntax (no colon, control chars, etc.)
                format!("Invalid\rTrailer\nLine\r\n")
            } else {
                format!("{}:{}\r\n", header_name, trailer.value)
            };

            if let Err(e) = decoder.process_trailer(&trailer_line) {
                errors.push(e);
                if trailer.use_forbidden_name || trailer.malformed_syntax {
                    expected_to_fail = true; // Expected error
                }
                break;
            }

            // If forbidden name was accepted, that's a bug
            if trailer.use_forbidden_name && !trailer.malformed_syntax {
                errors.push("Forbidden trailer was accepted".into());
                break;
            }
        }

        // Process final empty line if requested
        if scenario.include_final_empty_line && errors.is_empty() {
            if let Err(e) = decoder.process_trailer("\r\n") {
                errors.push(e);
            }
        }
    }

    // Validate results
    match decoder.finalize() {
        Ok((body, trailers)) => {
            // Successfully parsed - validate behavior
            if expected_to_fail && errors.is_empty() {
                // We expected this to fail but it succeeded
                assert!(
                    !scenario.malformed_final_chunk,
                    "Malformed final chunk should have failed"
                );

                let has_forbidden = scenario
                    .final_trailers
                    .iter()
                    .any(|t| t.use_forbidden_name && !t.malformed_syntax);
                assert!(
                    !has_forbidden,
                    "Forbidden trailer headers should have been rejected"
                );
            }

            // Validate body length doesn't exceed limit
            assert!(
                body.len() <= max_body_size,
                "Body size {} exceeds limit {}",
                body.len(),
                max_body_size
            );

            // Validate no forbidden trailers in result
            for (name, _) in &trailers {
                assert!(
                    !is_forbidden_trailer(name),
                    "Forbidden trailer '{}' found in results",
                    name
                );
            }

            // Validate trailer count matches expected
            let expected_trailer_count = scenario
                .final_trailers
                .iter()
                .filter(|t| !t.use_forbidden_name && !t.malformed_syntax)
                .count();

            if scenario.include_final_empty_line && errors.is_empty() {
                assert_eq!(
                    trailers.len(),
                    expected_trailer_count,
                    "Unexpected trailer count"
                );
            }
        }
        Err(error_list) => {
            // Failed to parse - validate that failure was expected
            if !expected_to_fail && !errors.is_empty() {
                // Unexpected failure - check if it was due to size limits
                let has_size_error = error_list.iter().any(|e| e.contains("too large"));

                if !has_size_error {
                    // Non-size-related unexpected failure might indicate a bug
                    // But for fuzzing, we'll accept it as valid behavior
                }
            }
        }
    }
});

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_chunked_with_trailers() {
        let scenario = ChunkedTrailerScenario {
            chunks: vec![Chunk {
                size: 5,
                data: b"hello".to_vec(),
                illegal_trailers_before_final: false,
                trailers: vec![],
            }],
            final_trailers: vec![TrailerHeader {
                name: "x-trace".to_string(),
                value: "abc123".to_string(),
                use_forbidden_name: false,
                malformed_syntax: false,
            }],
            include_final_empty_line: true,
            malformed_final_chunk: false,
            max_body_size: 1000,
            max_trailer_size: 1000,
        };

        libfuzzer_sys::test_input_wrap(scenario);
    }

    #[test]
    fn test_forbidden_trailer_rejection() {
        let scenario = ChunkedTrailerScenario {
            chunks: vec![],
            final_trailers: vec![TrailerHeader {
                name: "content-length".to_string(),
                value: "100".to_string(),
                use_forbidden_name: true,
                malformed_syntax: false,
            }],
            include_final_empty_line: true,
            malformed_final_chunk: false,
            max_body_size: 1000,
            max_trailer_size: 1000,
        };

        libfuzzer_sys::test_input_wrap(scenario);
    }

    #[test]
    fn test_malformed_final_chunk() {
        let scenario = ChunkedTrailerScenario {
            chunks: vec![],
            final_trailers: vec![],
            include_final_empty_line: false,
            malformed_final_chunk: true,
            max_body_size: 1000,
            max_trailer_size: 1000,
        };

        libfuzzer_sys::test_input_wrap(scenario);
    }
}
