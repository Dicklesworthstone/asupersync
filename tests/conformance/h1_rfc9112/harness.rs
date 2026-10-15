#![allow(warnings)]
#![allow(clippy::all)]
//! HTTP/1.1 conformance test harness.
//!
//! Provides testing infrastructure for RFC 9112 HTTP/1.1 conformance,
//! focusing on chunked transfer-encoding edge cases and compliance.

use asupersync::bytes::BytesMut;
use asupersync::codec::Decoder;
use asupersync::http::h1::codec::{Http1Codec, HttpError};
use std::time::Instant;

/// Requirement levels per RFC 2119.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[allow(dead_code)]
pub enum RequirementLevel {
    /// MUST requirement (mandatory).
    Must,
    /// SHOULD requirement (recommended).
    Should,
    /// MAY requirement (optional).
    May,
}

/// Test verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[allow(dead_code)]
pub enum TestVerdict {
    /// Test passed.
    Pass,
    /// Test failed unexpectedly.
    Fail,
    /// Test was skipped.
    Skipped,
    /// Test failed as expected (known limitation).
    ExpectedFailure,
}

/// Test categories for HTTP/1.1 conformance.
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[allow(dead_code)]
pub enum H1TestCategory {
    /// Chunked transfer-encoding parsing.
    ChunkedEncoding,
    /// Chunk extension parameter handling.
    ChunkExtensions,
    /// Trailer field processing.
    TrailerFields,
    /// CRLF vs LF line ending tolerance.
    LineEndings,
    /// Hex case sensitivity testing.
    HexCaseSensitivity,
    /// Resource limits and security.
    ResourceLimits,
    /// Transfer coding stacking.
    TransferCoding,
    /// Error handling and edge cases.
    ErrorHandling,
}

/// Result of a single conformance test.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[allow(dead_code)]
pub struct H1ConformanceResult {
    pub test_id: String,
    pub description: String,
    pub category: H1TestCategory,
    pub requirement_level: RequirementLevel,
    pub verdict: TestVerdict,
    pub error_message: Option<String>,
    pub execution_time_ms: u64,
}

/// Decoded HTTP/1.1 request result.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct DecodedRequest {
    pub method: String,
    pub uri: String,
    pub version: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    pub trailers: Vec<(String, String)>,
}

/// HTTP/1.1 conformance test harness.
#[allow(dead_code)]
pub struct H1ConformanceHarness {
    codec: Http1Codec,
}

#[allow(dead_code)]

impl H1ConformanceHarness {
    /// Create a new HTTP/1.1 conformance test harness.
    #[allow(dead_code)]
    pub fn new() -> Self {
        Self {
            codec: Http1Codec::new(),
        }
    }

    /// Decode a chunked HTTP/1.1 request.
    #[allow(dead_code)]
    pub fn decode_chunked_request(&self, data: &[u8]) -> Result<DecodedRequest, HttpError> {
        self.decode_chunked_request_with_remainder(data)
            .map(|(request, _remaining)| request)
    }

    /// Decode a chunked HTTP/1.1 request and preserve any pipelined remainder.
    #[allow(dead_code)]
    pub fn decode_chunked_request_with_remainder(
        &self,
        data: &[u8],
    ) -> Result<(DecodedRequest, Vec<u8>), HttpError> {
        // Create a mutable copy for decoding
        let mut codec = Http1Codec::new();
        let mut buf = BytesMut::from(data);

        match codec.decode(&mut buf) {
            Ok(Some(req)) => Ok((
                DecodedRequest {
                    method: req.method.to_string(),
                    uri: req.uri,
                    version: req.version.to_string(),
                    headers: req.headers,
                    body: req.body,
                    trailers: req.trailers,
                },
                buf.to_vec(),
            )),
            Ok(None) => Err(HttpError::BadChunkedEncoding), // Incomplete
            Err(e) => Err(e),
        }
    }

    /// Run all conformance tests.
    #[allow(dead_code)]
    pub fn run_all_tests(&self) -> Vec<H1ConformanceResult> {
        let mut results = Vec::new();

        // Chunked encoding basic compliance
        results.extend(self.test_chunked_encoding_basic());
        results.extend(self.test_chunked_encoding_boundaries());

        // Chunk extensions (RFC 9112 §7.1.1)
        results.extend(self.test_chunk_extensions());

        // Trailer fields (RFC 9112 §7.1.2)
        results.extend(self.test_trailer_fields());

        // CRLF/LF tolerance
        results.extend(self.test_line_ending_tolerance());

        // Hex case variants
        results.extend(self.test_hex_case_variants());

        // Resource limits
        results.extend(self.test_resource_limits());

        // Transfer coding stacking
        results.extend(self.test_transfer_coding_stacking());

        // Error handling
        results.extend(self.test_error_handling());

        results
    }

    /// Test basic chunked encoding conformance.
    #[allow(dead_code)]
    fn test_chunked_encoding_basic(&self) -> Vec<H1ConformanceResult> {
        let mut results = Vec::new();

        // Test 1: Simple chunked request
        let start = Instant::now();
        let test_data = concat!(
            "POST /upload HTTP/1.1\r\n",
            "Transfer-Encoding: chunked\r\n",
            "\r\n",
            "5\r\nhello\r\n",
            "6\r\n world\r\n",
            "0\r\n\r\n"
        )
        .as_bytes();

        let result = self.decode_chunked_request(test_data);
        let elapsed = start.elapsed();
        let error_message = match &result {
            Err(e) => Some(format!("Decode error: {e:?}")),
            _ => None,
        };

        results.push(H1ConformanceResult {
            test_id: "rfc9112_chunked_basic".to_string(),
            description: "Basic chunked encoding with multiple chunks".to_string(),
            category: H1TestCategory::ChunkedEncoding,
            requirement_level: RequirementLevel::Must,
            verdict: match result {
                Ok(req) if req.body == b"hello world" => TestVerdict::Pass,
                Ok(_) => TestVerdict::Fail,
                Err(_) => TestVerdict::Fail,
            },
            error_message,
            execution_time_ms: elapsed.as_millis() as u64,
        });

        // Test 2: Empty chunked request
        let start = Instant::now();
        let test_data = concat!(
            "POST /empty HTTP/1.1\r\n",
            "Transfer-Encoding: chunked\r\n",
            "\r\n",
            "0\r\n\r\n"
        )
        .as_bytes();

        let result = self.decode_chunked_request(test_data);
        let elapsed = start.elapsed();
        let error_message = match &result {
            Err(e) => Some(format!("Decode error: {e:?}")),
            _ => None,
        };

        results.push(H1ConformanceResult {
            test_id: "rfc9112_chunked_empty".to_string(),
            description: "Empty chunked request with only terminating chunk".to_string(),
            category: H1TestCategory::ChunkedEncoding,
            requirement_level: RequirementLevel::Must,
            verdict: match result {
                Ok(req) if req.body.is_empty() => TestVerdict::Pass,
                Ok(_) => TestVerdict::Fail,
                Err(_) => TestVerdict::Fail,
            },
            error_message,
            execution_time_ms: elapsed.as_millis() as u64,
        });

        results
    }

    /// Test chunked decoding boundaries and pipelined follow-up preservation.
    #[allow(dead_code)]
    fn test_chunked_encoding_boundaries(&self) -> Vec<H1ConformanceResult> {
        let mut results = Vec::new();

        let start = Instant::now();
        let test_data = concat!(
            "POST /upload HTTP/1.1\r\n",
            "Transfer-Encoding: chunked\r\n",
            "\r\n",
            "5\r\nhello\r\n",
            "0\r\n\r\n",
            "GET /next HTTP/1.1\r\n",
            "Host: example.com\r\n",
            "\r\n"
        )
        .as_bytes();

        let result = self.decode_chunked_request_with_remainder(test_data);
        let elapsed = start.elapsed();
        let error_message = match &result {
            Err(e) => Some(format!("Decode error: {e:?}")),
            _ => None,
        };

        results.push(H1ConformanceResult {
            test_id: "rfc9112_chunked_pipelined_followup".to_string(),
            description: "Chunked decoder must preserve the next pipelined request boundary"
                .to_string(),
            category: H1TestCategory::ChunkedEncoding,
            requirement_level: RequirementLevel::Must,
            verdict: match result {
                Ok((req, remaining))
                    if req.body == b"hello"
                        && req.trailers.is_empty()
                        && remaining.starts_with(b"GET /next HTTP/1.1\r\n") =>
                {
                    TestVerdict::Pass
                }
                Ok(_) => TestVerdict::Fail,
                Err(_) => TestVerdict::Fail,
            },
            error_message,
            execution_time_ms: elapsed.as_millis() as u64,
        });

        results
    }

    /// Test chunk extension parameter handling.
    #[allow(dead_code)]
    fn test_chunk_extensions(&self) -> Vec<H1ConformanceResult> {
        let mut results = Vec::new();

        // Test: Chunk with extension parameters
        let start = Instant::now();
        let test_data = concat!(
            "POST /test HTTP/1.1\r\n",
            "Transfer-Encoding: chunked\r\n",
            "\r\n",
            "5;name=value;other=param\r\nhello\r\n",
            "0\r\n\r\n"
        )
        .as_bytes();

        let result = self.decode_chunked_request(test_data);
        let elapsed = start.elapsed();
        let error_message = match &result {
            Err(e) => Some(format!("Decode error: {e:?}")),
            _ => None,
        };

        results.push(H1ConformanceResult {
            test_id: "rfc9112_chunk_ext_basic".to_string(),
            description: "Chunk extensions should be parsed and ignored".to_string(),
            category: H1TestCategory::ChunkExtensions,
            requirement_level: RequirementLevel::Must,
            verdict: match result {
                Ok(req) if req.body == b"hello" => TestVerdict::Pass,
                Ok(_) => TestVerdict::Fail,
                Err(_) => TestVerdict::Fail,
            },
            error_message,
            execution_time_ms: elapsed.as_millis() as u64,
        });

        // Test: Chunk extension with quoted string (RFC 9112 allows this)
        let start = Instant::now();
        let test_data = concat!(
            "POST /test HTTP/1.1\r\n",
            "Transfer-Encoding: chunked\r\n",
            "\r\n",
            "5;name=\"quoted value\"\r\nhello\r\n",
            "0\r\n\r\n"
        )
        .as_bytes();

        let result = self.decode_chunked_request(test_data);
        let elapsed = start.elapsed();
        let error_message = match &result {
            Err(e) => Some(format!("Decode error: {e:?}")),
            _ => None,
        };

        results.push(H1ConformanceResult {
            test_id: "rfc9112_chunk_ext_quoted".to_string(),
            description: "Chunk extensions with quoted strings".to_string(),
            category: H1TestCategory::ChunkExtensions,
            requirement_level: RequirementLevel::Should,
            verdict: match result {
                Ok(req) if req.body == b"hello" => TestVerdict::Pass,
                Ok(_) => TestVerdict::Fail,
                Err(_) => TestVerdict::Fail,
            },
            error_message,
            execution_time_ms: elapsed.as_millis() as u64,
        });

        results
    }

    /// Test trailer field processing.
    #[allow(dead_code)]
    fn test_trailer_fields(&self) -> Vec<H1ConformanceResult> {
        let mut results = Vec::new();

        // Test: Basic trailer fields
        let start = Instant::now();
        let test_data = concat!(
            "POST /test HTTP/1.1\r\n",
            "Transfer-Encoding: chunked\r\n",
            "\r\n",
            "5\r\nhello\r\n",
            "0\r\n",
            "X-Trailer: value1\r\n",
            "Y-Trailer: value2\r\n",
            "\r\n"
        )
        .as_bytes();

        let result = self.decode_chunked_request(test_data);
        let elapsed = start.elapsed();
        let error_message = match &result {
            Err(e) => Some(format!("Decode error: {e:?}")),
            _ => None,
        };

        results.push(H1ConformanceResult {
            test_id: "rfc9112_trailers_basic".to_string(),
            description: "Basic trailer field processing after final chunk".to_string(),
            category: H1TestCategory::TrailerFields,
            requirement_level: RequirementLevel::Must,
            verdict: match result {
                Ok(req)
                    if req.body == b"hello"
                        && req.trailers
                            == vec![
                                ("X-Trailer".to_string(), "value1".to_string()),
                                ("Y-Trailer".to_string(), "value2".to_string()),
                            ] =>
                {
                    TestVerdict::Pass
                }
                Ok(_) => TestVerdict::Fail,
                Err(_) => TestVerdict::Fail,
            },
            error_message,
            execution_time_ms: elapsed.as_millis() as u64,
        });

        // Test: Empty trailer section is accepted and leaves no phantom trailers.
        let start = Instant::now();
        let test_data = concat!(
            "POST /test HTTP/1.1\r\n",
            "Transfer-Encoding: chunked\r\n",
            "\r\n",
            "5\r\nhello\r\n",
            "0\r\n",
            "\r\n"
        )
        .as_bytes();

        let result = self.decode_chunked_request(test_data);
        let elapsed = start.elapsed();
        let error_message = match &result {
            Err(e) => Some(format!("Decode error: {e:?}")),
            _ => None,
        };

        results.push(H1ConformanceResult {
            test_id: "rfc9112_trailers_empty_section".to_string(),
            description: "Empty trailer section after final chunk is valid".to_string(),
            category: H1TestCategory::TrailerFields,
            requirement_level: RequirementLevel::Must,
            verdict: match result {
                Ok(req) if req.body == b"hello" && req.trailers.is_empty() => TestVerdict::Pass,
                Ok(_) => TestVerdict::Fail,
                Err(_) => TestVerdict::Fail,
            },
            error_message,
            execution_time_ms: elapsed.as_millis() as u64,
        });

        results
    }

    /// Test CRLF vs LF line ending tolerance.
    #[allow(dead_code)]
    fn test_line_ending_tolerance(&self) -> Vec<H1ConformanceResult> {
        let mut results = Vec::new();

        // Test: Mixed CRLF/LF (should be strict per RFC)
        let start = Instant::now();
        let test_data = concat!(
            "POST /test HTTP/1.1\r\n",
            "Transfer-Encoding: chunked\r\n",
            "\r\n",
            "5\nhello\r\n", // LF instead of CRLF in chunk size line
            "0\r\n\r\n"
        )
        .as_bytes();

        let result = self.decode_chunked_request(test_data);
        let elapsed = start.elapsed();

        results.push(H1ConformanceResult {
            test_id: "rfc9112_line_endings_strict".to_string(),
            description: "Mixed CRLF/LF should be rejected per RFC strictness".to_string(),
            category: H1TestCategory::LineEndings,
            requirement_level: RequirementLevel::Should,
            verdict: match result {
                Ok(_) => TestVerdict::Fail, // Should reject mixed line endings
                Err(_) => TestVerdict::Pass,
            },
            error_message: if result.is_ok() {
                Some("Mixed line endings were accepted but should be rejected".to_string())
            } else {
                None
            },
            execution_time_ms: elapsed.as_millis() as u64,
        });

        results
    }

    /// Test hex chunk size case variants.
    #[allow(dead_code)]
    fn test_hex_case_variants(&self) -> Vec<H1ConformanceResult> {
        let mut results = Vec::new();

        // Test: Mixed case hex digits
        let start = Instant::now();
        let test_data = concat!(
            "POST /test HTTP/1.1\r\n",
            "Transfer-Encoding: chunked\r\n",
            "\r\n",
            "A\r\nhelloworld\r\n", // Uppercase A
            "a\r\nhelloworld\r\n", // Lowercase a
            "0\r\n\r\n"
        )
        .as_bytes();

        let result = self.decode_chunked_request(test_data);
        let elapsed = start.elapsed();
        let error_message = match &result {
            Err(e) => Some(format!("Decode error: {e:?}")),
            _ => None,
        };

        results.push(H1ConformanceResult {
            test_id: "rfc9112_hex_case_mixed".to_string(),
            description: "Mixed case hex digits should be accepted".to_string(),
            category: H1TestCategory::HexCaseSensitivity,
            requirement_level: RequirementLevel::Must,
            verdict: match result {
                Ok(req) if req.body == b"helloworldhelloworld" => TestVerdict::Pass,
                Ok(_) => TestVerdict::Fail,
                Err(_) => TestVerdict::Fail,
            },
            error_message,
            execution_time_ms: elapsed.as_millis() as u64,
        });

        results
    }

    /// Test resource limits and security.
    #[allow(dead_code)]
    fn test_resource_limits(&self) -> Vec<H1ConformanceResult> {
        let mut results = Vec::new();

        // Test: Oversized chunk size line
        let start = Instant::now();
        let oversized_chunk_size = "F".repeat(1000); // Way too large hex number
        let test_data = format!(
            "POST /test HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n{}\r\nhello\r\n0\r\n\r\n",
            oversized_chunk_size
        );

        let result = self.decode_chunked_request(test_data.as_bytes());
        let elapsed = start.elapsed();

        results.push(H1ConformanceResult {
            test_id: "rfc9112_chunk_size_limit".to_string(),
            description: "Oversized chunk size headers should be rejected".to_string(),
            category: H1TestCategory::ResourceLimits,
            requirement_level: RequirementLevel::Must,
            verdict: match result {
                Ok(_) => TestVerdict::Fail, // Should reject oversized
                Err(_) => TestVerdict::Pass,
            },
            error_message: if result.is_ok() {
                Some("Oversized chunk size was accepted but should be rejected".to_string())
            } else {
                None
            },
            execution_time_ms: elapsed.as_millis() as u64,
        });

        results
    }

    /// Test transfer coding stacking.
    #[allow(dead_code)]
    fn test_transfer_coding_stacking(&self) -> Vec<H1ConformanceResult> {
        let mut results = Vec::new();

        // Test: Multiple transfer encodings (should be rejected in current impl)
        let start = Instant::now();
        let test_data = concat!(
            "POST /test HTTP/1.1\r\n",
            "Transfer-Encoding: gzip, chunked\r\n",
            "\r\n",
            "0\r\n\r\n"
        )
        .as_bytes();

        let result = self.decode_chunked_request(test_data);
        let elapsed = start.elapsed();

        results.push(H1ConformanceResult {
            test_id: "rfc9112_transfer_stacking".to_string(),
            description: "Transfer coding stacking (gzip,chunked) handling".to_string(),
            category: H1TestCategory::TransferCoding,
            requirement_level: RequirementLevel::Should,
            verdict: match result {
                Ok(_) => TestVerdict::ExpectedFailure, // Current impl rejects stacking
                Err(_) => TestVerdict::Pass,
            },
            error_message: Some("Current implementation only supports chunked-only".to_string()),
            execution_time_ms: elapsed.as_millis() as u64,
        });

        results
    }

    /// Test error handling edge cases.
    #[allow(dead_code)]
    fn test_error_handling(&self) -> Vec<H1ConformanceResult> {
        let mut results = Vec::new();

        // Test: Invalid hex characters
        let start = Instant::now();
        let test_data = concat!(
            "POST /test HTTP/1.1\r\n",
            "Transfer-Encoding: chunked\r\n",
            "\r\n",
            "G\r\nhello\r\n", // G is not valid hex
            "0\r\n\r\n"
        )
        .as_bytes();

        let result = self.decode_chunked_request(test_data);
        let elapsed = start.elapsed();

        results.push(H1ConformanceResult {
            test_id: "rfc9112_invalid_hex".to_string(),
            description: "Invalid hex characters should be rejected".to_string(),
            category: H1TestCategory::ErrorHandling,
            requirement_level: RequirementLevel::Must,
            verdict: match result {
                Ok(_) => TestVerdict::Fail,
                Err(_) => TestVerdict::Pass,
            },
            error_message: if result.is_ok() {
                Some("Invalid hex was accepted but should be rejected".to_string())
            } else {
                None
            },
            execution_time_ms: elapsed.as_millis() as u64,
        });

        // Test: Missing final chunk
        let start = Instant::now();
        let test_data = concat!(
            "POST /test HTTP/1.1\r\n",
            "Transfer-Encoding: chunked\r\n",
            "\r\n",
            "5\r\nhello\r\n" // Missing 0\r\n\r\n terminator
        )
        .as_bytes();

        let result = self.decode_chunked_request(test_data);
        let elapsed = start.elapsed();

        results.push(H1ConformanceResult {
            test_id: "rfc9112_missing_terminator".to_string(),
            description: "Missing final chunk terminator should be rejected".to_string(),
            category: H1TestCategory::ErrorHandling,
            requirement_level: RequirementLevel::Must,
            verdict: match result {
                Ok(_) => TestVerdict::Fail,
                Err(_) => TestVerdict::Pass,
            },
            error_message: if result.is_ok() {
                Some("Incomplete chunked stream was accepted".to_string())
            } else {
                None
            },
            execution_time_ms: elapsed.as_millis() as u64,
        });

        results
    }
}

impl Default for H1ConformanceHarness {
    #[allow(dead_code)]
    fn default() -> Self {
        Self::new()
    }
}
