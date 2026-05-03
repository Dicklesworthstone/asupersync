#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use libfuzzer_sys::fuzz_target;

/// HTTP/1.1 chunked encoding terminator validation testing.
/// Per RFC 9112, chunked body must end with "0\r\n\r\n" terminator.
/// Missing or incomplete terminator (truncated stream) must be error.
///
/// Tests:
/// - Chunked body ending abruptly without "0\r\n\r\n" terminator
/// - Incomplete final chunk: "0", "0\r", "0\r\n" without final "\r\n"
/// - Malformed final chunk terminators
/// - Valid chunked bodies with proper termination (should succeed)
/// - Various truncation points in chunk sequence
/// - Trailer headers before missing terminator
/// - Empty chunks and edge cases

#[derive(Arbitrary, Debug)]
struct FuzzInput {
    /// HTTP/1.1 chunked request/response
    chunked_message: ChunkedMessage,
}

#[derive(Arbitrary, Debug, Clone)]
struct ChunkedMessage {
    /// Initial HTTP headers (before chunked body)
    headers: Vec<String>,
    /// Sequence of chunks
    chunks: Vec<ChunkData>,
    /// Termination scenario
    termination: TerminationScenario,
    /// Optional trailer headers (before final terminator)
    trailer_headers: Vec<String>,
}

#[derive(Arbitrary, Debug, Clone)]
struct ChunkData {
    /// Chunk size in hex
    size: u32,
    /// Optional chunk extensions
    extensions: Vec<String>,
    /// Chunk data
    data: Vec<u8>,
}

#[derive(Arbitrary, Debug, Clone)]
enum TerminationScenario {
    /// Proper termination with "0\r\n\r\n"
    Proper,
    /// Missing terminator completely (abrupt end)
    Missing,
    /// Incomplete terminator scenarios
    IncompleteZero, // Just "0"
    IncompleteZeroR,   // "0\r"
    IncompleteZeroRN,  // "0\r\n"
    IncompleteZeroRNR, // "0\r\n\r"
    /// Malformed terminator
    MalformedZero(String), // Custom malformed chunk
    /// Extra data after proper terminator
    ExtraDataAfter(Vec<u8>),
}

/// HTTP/1.1 chunked encoding parser state
#[derive(Debug, PartialEq)]
enum ChunkedParserState {
    ExpectingChunkSize,
    ExpectingChunkData(usize), // remaining bytes
    ExpectingChunkTrailer,
    ExpectingFinalTrailer,
    Complete,
    Error(String),
}

/// Mock HTTP/1.1 chunked encoding parser with termination validation
struct MockH1ChunkedParser {
    state: ChunkedParserState,
    total_bytes_read: usize,
    chunks_received: Vec<Vec<u8>>,
    trailer_headers: Vec<String>,
    errors: Vec<String>,
}

impl MockH1ChunkedParser {
    fn new() -> Self {
        Self {
            state: ChunkedParserState::ExpectingChunkSize,
            total_bytes_read: 0,
            chunks_received: Vec::new(),
            trailer_headers: Vec::new(),
            errors: Vec::new(),
        }
    }

    /// Parse chunked message with termination validation
    fn parse_chunked_message(&mut self, message: &ChunkedMessage) -> Result<(), String> {
        // Build raw chunked data
        let raw_data = self.build_raw_chunked_data(message);

        // Parse the raw chunked data
        self.parse_chunked_data(&raw_data)
    }

    /// Build raw HTTP/1.1 chunked data from message structure
    fn build_raw_chunked_data(&self, message: &ChunkedMessage) -> Vec<u8> {
        let mut data = Vec::new();

        // Add regular chunks
        for chunk in &message.chunks {
            // Chunk size line: "SIZE[;extensions]\r\n"
            data.extend(format!("{:x}", chunk.size).as_bytes());

            for ext in &chunk.extensions {
                data.extend(format!(";{}", ext).as_bytes());
            }
            data.extend(b"\r\n");

            // Chunk data
            if chunk.size > 0 {
                let actual_data_len = (chunk.size as usize).min(chunk.data.len());
                data.extend(&chunk.data[..actual_data_len]);
            }
            data.extend(b"\r\n");
        }

        // Add trailer headers if present
        for trailer in &message.trailer_headers {
            data.extend(trailer.as_bytes());
            data.extend(b"\r\n");
        }

        // Add termination based on scenario
        match &message.termination {
            TerminationScenario::Proper => {
                data.extend(b"0\r\n\r\n");
            }
            TerminationScenario::Missing => {
                // No terminator - abrupt end
            }
            TerminationScenario::IncompleteZero => {
                data.extend(b"0");
            }
            TerminationScenario::IncompleteZeroR => {
                data.extend(b"0\r");
            }
            TerminationScenario::IncompleteZeroRN => {
                data.extend(b"0\r\n");
            }
            TerminationScenario::IncompleteZeroRNR => {
                data.extend(b"0\r\n\r");
            }
            TerminationScenario::MalformedZero(malformed) => {
                data.extend(malformed.as_bytes());
            }
            TerminationScenario::ExtraDataAfter(extra) => {
                data.extend(b"0\r\n\r\n");
                data.extend(extra);
            }
        }

        data
    }

    /// Parse raw chunked data
    fn parse_chunked_data(&mut self, data: &[u8]) -> Result<(), String> {
        let mut pos = 0;

        while pos < data.len() {
            match &self.state {
                ChunkedParserState::ExpectingChunkSize => {
                    pos = self.parse_chunk_size_line(data, pos)?;
                }
                ChunkedParserState::ExpectingChunkData(remaining) => {
                    pos = self.parse_chunk_data(data, pos, *remaining)?;
                }
                ChunkedParserState::ExpectingChunkTrailer => {
                    pos = self.parse_chunk_trailer(data, pos)?;
                }
                ChunkedParserState::ExpectingFinalTrailer => {
                    pos = self.parse_final_trailer(data, pos)?;
                }
                ChunkedParserState::Complete => {
                    // Should not have more data after completion
                    return Err("Unexpected data after chunked encoding completion".into());
                }
                ChunkedParserState::Error(error) => {
                    return Err(error.clone());
                }
            }
        }

        // Check if we're in a valid terminal state
        match &self.state {
            ChunkedParserState::Complete => Ok(()),
            ChunkedParserState::ExpectingChunkSize => {
                Err("Truncated chunked encoding: expecting chunk size".into())
            }
            ChunkedParserState::ExpectingChunkData(_) => {
                Err("Truncated chunked encoding: incomplete chunk data".into())
            }
            ChunkedParserState::ExpectingChunkTrailer => {
                Err("Truncated chunked encoding: missing chunk trailer (\\r\\n)".into())
            }
            ChunkedParserState::ExpectingFinalTrailer => {
                Err("Truncated chunked encoding: missing final terminator (\\r\\n)".into())
            }
            ChunkedParserState::Error(error) => Err(error.clone()),
        }
    }

    /// Parse chunk size line: "SIZE[;extensions]\r\n"
    fn parse_chunk_size_line(&mut self, data: &[u8], start_pos: usize) -> Result<usize, String> {
        // Look for \r\n
        if let Some(line_end) = self.find_crlf(data, start_pos) {
            let line = &data[start_pos..line_end];
            let line_str = String::from_utf8_lossy(line);

            // Parse chunk size (hex before any semicolon)
            let size_str = line_str.split(';').next().unwrap_or("").trim();

            if size_str.is_empty() {
                return Err("Invalid chunk size line: empty size".into());
            }

            let chunk_size = u32::from_str_radix(size_str, 16)
                .map_err(|_| format!("Invalid hex chunk size: {}", size_str))?;

            if chunk_size == 0 {
                // Final chunk - expect final trailer
                self.state = ChunkedParserState::ExpectingFinalTrailer;
            } else {
                // Regular chunk - expect data
                self.state = ChunkedParserState::ExpectingChunkData(chunk_size as usize);
            }

            Ok(line_end + 2) // Skip past \r\n
        } else {
            Err("Truncated chunk size line: missing \\r\\n".into())
        }
    }

    /// Parse chunk data
    fn parse_chunk_data(
        &mut self,
        data: &[u8],
        start_pos: usize,
        expected_size: usize,
    ) -> Result<usize, String> {
        let available = data.len() - start_pos;

        if available < expected_size {
            return Err(format!(
                "Truncated chunk data: expected {} bytes, only {} available",
                expected_size, available
            ));
        }

        // Read chunk data
        let chunk_data = data[start_pos..start_pos + expected_size].to_vec();
        self.chunks_received.push(chunk_data);
        self.total_bytes_read += expected_size;

        // Expect chunk trailer (\r\n)
        self.state = ChunkedParserState::ExpectingChunkTrailer;

        Ok(start_pos + expected_size)
    }

    /// Parse chunk trailer (\r\n after chunk data)
    fn parse_chunk_trailer(&mut self, data: &[u8], start_pos: usize) -> Result<usize, String> {
        if start_pos + 1 < data.len() && &data[start_pos..start_pos + 2] == b"\r\n" {
            self.state = ChunkedParserState::ExpectingChunkSize;
            Ok(start_pos + 2)
        } else {
            Err("Missing chunk trailer: expected \\r\\n after chunk data".into())
        }
    }

    /// Parse final trailer (\r\n after "0\r\n")
    fn parse_final_trailer(&mut self, data: &[u8], start_pos: usize) -> Result<usize, String> {
        if start_pos + 1 < data.len() && &data[start_pos..start_pos + 2] == b"\r\n" {
            self.state = ChunkedParserState::Complete;
            Ok(start_pos + 2)
        } else {
            Err("Missing final terminator: expected \\r\\n after final chunk".into())
        }
    }

    /// Find next \r\n sequence
    fn find_crlf(&self, data: &[u8], start_pos: usize) -> Option<usize> {
        for i in start_pos..data.len().saturating_sub(1) {
            if data[i] == b'\r' && data[i + 1] == b'\n' {
                return Some(i);
            }
        }
        None
    }

    /// Get parsed chunks
    fn get_chunks(&self) -> &[Vec<u8>] {
        &self.chunks_received
    }

    /// Get parser state
    fn get_state(&self) -> &ChunkedParserState {
        &self.state
    }

    /// Check if parsing completed successfully
    fn is_complete(&self) -> bool {
        matches!(self.state, ChunkedParserState::Complete)
    }
}

fuzz_target!(|data: &[u8]| {
    let mut u = Unstructured::new(data);
    let input: FuzzInput = match u.arbitrary() {
        Ok(input) => input,
        Err(_) => return, // Skip invalid inputs
    };

    // Limit sizes to prevent timeouts
    if input.chunked_message.chunks.len() > 10 {
        return;
    }

    if input.chunked_message.chunks.iter().any(|c| c.size > 10000) {
        return;
    }

    let mut parser = MockH1ChunkedParser::new();
    let result = parser.parse_chunked_message(&input.chunked_message);

    // Test 1: Missing or incomplete terminators should fail
    match &input.chunked_message.termination {
        TerminationScenario::Missing
        | TerminationScenario::IncompleteZero
        | TerminationScenario::IncompleteZeroR
        | TerminationScenario::IncompleteZeroRN
        | TerminationScenario::IncompleteZeroRNR => {
            assert!(
                result.is_err(),
                "Missing/incomplete terminator should cause parse error"
            );

            if let Err(error_msg) = &result {
                assert!(
                    error_msg.contains("Truncated") || error_msg.contains("Missing"),
                    "Error should indicate truncation/missing terminator: {}",
                    error_msg
                );
            }
        }
        TerminationScenario::MalformedZero(malformed) => {
            // Malformed terminators should generally fail
            if !malformed.starts_with("0\r\n\r\n") {
                assert!(
                    result.is_err(),
                    "Malformed terminator should cause parse error: {}",
                    malformed
                );
            }
        }
        TerminationScenario::Proper => {
            // Check if all chunks have valid sizes
            let has_valid_chunks = input
                .chunked_message
                .chunks
                .iter()
                .all(|chunk| chunk.data.len() >= chunk.size as usize);

            if has_valid_chunks {
                assert!(
                    result.is_ok(),
                    "Properly terminated chunked encoding should succeed"
                );

                assert!(
                    parser.is_complete(),
                    "Parser should be in complete state for proper termination"
                );

                // Verify all non-zero chunks were parsed
                let expected_chunks: Vec<_> = input
                    .chunked_message
                    .chunks
                    .iter()
                    .filter(|c| c.size > 0)
                    .count();
                let parsed_chunks = parser.get_chunks().len();

                assert_eq!(
                    parsed_chunks, expected_chunks,
                    "Should parse all non-zero chunks"
                );
            }
        }
        TerminationScenario::ExtraDataAfter(_) => {
            // Extra data after proper terminator should fail
            assert!(
                result.is_err(),
                "Extra data after terminator should cause error"
            );

            if let Err(error_msg) = &result {
                assert!(
                    error_msg.contains("Unexpected data"),
                    "Error should mention unexpected data: {}",
                    error_msg
                );
            }
        }
    }

    // Test 2: Verify chunk size validation
    for chunk in &input.chunked_message.chunks {
        if chunk.data.len() < chunk.size as usize {
            assert!(
                result.is_err(),
                "Insufficient chunk data should cause error"
            );
            return;
        }
    }

    // Test 3: Parser state consistency
    match parser.get_state() {
        ChunkedParserState::Complete => {
            assert!(
                matches!(
                    input.chunked_message.termination,
                    TerminationScenario::Proper
                ),
                "Complete state should only occur with proper termination"
            );
        }
        ChunkedParserState::Error(_) => {
            assert!(
                result.is_err(),
                "Error state should correspond to failed result"
            );
        }
        _ => {
            // Incomplete states should have error result
            if matches!(
                input.chunked_message.termination,
                TerminationScenario::Proper
            ) {
                // Proper termination with incomplete state suggests other parse error
                assert!(
                    result.is_err(),
                    "Incomplete state with proper termination suggests parse error"
                );
            }
        }
    }
});

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_proper_termination() {
        let message = ChunkedMessage {
            headers: vec!["Transfer-Encoding: chunked".to_string()],
            chunks: vec![
                ChunkData {
                    size: 5,
                    extensions: vec![],
                    data: b"hello".to_vec(),
                },
                ChunkData {
                    size: 5,
                    extensions: vec![],
                    data: b"world".to_vec(),
                },
            ],
            termination: TerminationScenario::Proper,
            trailer_headers: vec![],
        };

        let mut parser = MockH1ChunkedParser::new();
        let result = parser.parse_chunked_message(&message);

        assert!(
            result.is_ok(),
            "Properly terminated chunked message should succeed"
        );
        assert!(parser.is_complete());
        assert_eq!(parser.get_chunks().len(), 2);
    }

    #[test]
    fn test_missing_terminator() {
        let message = ChunkedMessage {
            headers: vec![],
            chunks: vec![ChunkData {
                size: 5,
                extensions: vec![],
                data: b"hello".to_vec(),
            }],
            termination: TerminationScenario::Missing,
            trailer_headers: vec![],
        };

        let mut parser = MockH1ChunkedParser::new();
        let result = parser.parse_chunked_message(&message);

        assert!(result.is_err(), "Missing terminator should cause error");
        assert!(result.unwrap_err().contains("Truncated"));
    }

    #[test]
    fn test_incomplete_zero_chunk() {
        let message = ChunkedMessage {
            headers: vec![],
            chunks: vec![ChunkData {
                size: 3,
                extensions: vec![],
                data: b"abc".to_vec(),
            }],
            termination: TerminationScenario::IncompleteZero,
            trailer_headers: vec![],
        };

        let mut parser = MockH1ChunkedParser::new();
        let result = parser.parse_chunked_message(&message);

        assert!(result.is_err(), "Incomplete zero chunk should cause error");
        assert!(
            result.unwrap_err().contains("Truncated") || result.unwrap_err().contains("missing")
        );
    }

    #[test]
    fn test_incomplete_zero_rn() {
        let message = ChunkedMessage {
            headers: vec![],
            chunks: vec![],
            termination: TerminationScenario::IncompleteZeroRN,
            trailer_headers: vec![],
        };

        let mut parser = MockH1ChunkedParser::new();
        let result = parser.parse_chunked_message(&message);

        assert!(result.is_err(), "Incomplete zero\\r\\n should cause error");
        assert!(result.unwrap_err().contains("Missing final terminator"));
    }

    #[test]
    fn test_extra_data_after_terminator() {
        let message = ChunkedMessage {
            headers: vec![],
            chunks: vec![ChunkData {
                size: 2,
                extensions: vec![],
                data: b"hi".to_vec(),
            }],
            termination: TerminationScenario::ExtraDataAfter(b"extra".to_vec()),
            trailer_headers: vec![],
        };

        let mut parser = MockH1ChunkedParser::new();
        let result = parser.parse_chunked_message(&message);

        assert!(
            result.is_err(),
            "Extra data after terminator should cause error"
        );
        assert!(result.unwrap_err().contains("Unexpected data"));
    }

    #[test]
    fn test_malformed_chunk_size() {
        let message = ChunkedMessage {
            headers: vec![],
            chunks: vec![ChunkData {
                size: 0,
                extensions: vec![],
                data: b"invalid".to_vec(),
            }],
            termination: TerminationScenario::MalformedZero("g\r\n\r\n".to_string()), // Invalid hex
            trailer_headers: vec![],
        };

        let mut parser = MockH1ChunkedParser::new();
        let result = parser.parse_chunked_message(&message);

        assert!(result.is_err(), "Malformed chunk size should cause error");
    }

    #[test]
    fn test_insufficient_chunk_data() {
        let message = ChunkedMessage {
            headers: vec![],
            chunks: vec![
                ChunkData {
                    size: 10,
                    extensions: vec![],
                    data: b"short".to_vec(),
                }, // Only 5 bytes
            ],
            termination: TerminationScenario::Proper,
            trailer_headers: vec![],
        };

        let mut parser = MockH1ChunkedParser::new();
        let result = parser.parse_chunked_message(&message);

        assert!(
            result.is_err(),
            "Insufficient chunk data should cause error"
        );
        assert!(result.unwrap_err().contains("Truncated chunk data"));
    }

    #[test]
    fn test_zero_size_chunks() {
        let message = ChunkedMessage {
            headers: vec![],
            chunks: vec![
                ChunkData {
                    size: 0,
                    extensions: vec![],
                    data: vec![],
                },
                ChunkData {
                    size: 3,
                    extensions: vec![],
                    data: b"end".to_vec(),
                },
            ],
            termination: TerminationScenario::Proper,
            trailer_headers: vec![],
        };

        let mut parser = MockH1ChunkedParser::new();
        let result = parser.parse_chunked_message(&message);

        assert!(result.is_ok(), "Zero-size chunks should be valid");
        assert_eq!(parser.get_chunks().len(), 1); // Only non-zero chunk counted
    }

    #[test]
    fn test_chunk_extensions() {
        let message = ChunkedMessage {
            headers: vec![],
            chunks: vec![ChunkData {
                size: 4,
                extensions: vec!["name=value".to_string()],
                data: b"test".to_vec(),
            }],
            termination: TerminationScenario::Proper,
            trailer_headers: vec![],
        };

        let mut parser = MockH1ChunkedParser::new();
        let result = parser.parse_chunked_message(&message);

        assert!(result.is_ok(), "Chunk extensions should be supported");
    }
}
