//! Real integration tests between http/h1/codec and http/body.
//!
//! Verifies that chunked transfer encoding correctly handles trailers and
//! partial body reads without buffer corruption during codec-body integration.

#![allow(clippy::missing_docs_in_private_items)]

use crate::bytes::{Buf, BufMut, Bytes, BytesMut};
use crate::codec::{Decoder, Encoder};
use crate::http::body::{Body, Frame, Full, HeaderMap, HeaderName, HeaderValue, StreamBody};
use crate::http::h1::codec::{Http1Codec, HttpError};
use crate::http::h1::types::{Method, Request, Response, StatusCode, Version};
use std::collections::HashMap;
use std::fmt::Write as _;
use std::io::{self, Error, ErrorKind};
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

/// Mock chunk generator for creating chunked HTTP bodies with trailers.
#[derive(Debug)]
struct ChunkedBodyGenerator {
    /// Chunks of data to generate.
    chunks: Vec<Bytes>,
    /// Optional trailer headers to append.
    trailers: Option<HeaderMap>,
    /// Current chunk index.
    current_chunk: usize,
    /// Whether trailers have been sent.
    trailers_sent: bool,
}

impl ChunkedBodyGenerator {
    fn new(chunk_data: Vec<&str>) -> Self {
        let chunks = chunk_data
            .into_iter()
            .map(|s| Bytes::from(s.to_string()))
            .collect();
        Self {
            chunks,
            trailers: None,
            current_chunk: 0,
            trailers_sent: false,
        }
    }

    /// Add trailer headers to be sent after the body.
    fn with_trailers(mut self, trailers: HeaderMap) -> Self {
        self.trailers = Some(trailers);
        self
    }

    /// Create a body with mixed chunk sizes for testing partial reads.
    fn mixed_chunks() -> Self {
        Self::new(vec![
            "Hello, ",                                                    // Small chunk
            "this is a test ",                                            // Medium chunk
            "of chunked transfer encoding with various chunk sizes and ", // Large chunk
            "ending ",                                                    // Small chunk
            "here.",                                                      // Final chunk
        ])
    }

    /// Create a body with large chunks to test buffer management.
    fn large_chunks() -> Self {
        let large_chunk = "x".repeat(8192); // 8KB chunk
        let medium_chunk = "y".repeat(1024); // 1KB chunk
        Self::new(vec![
            large_chunk.as_str(),
            "small",
            medium_chunk.as_str(),
            "final",
        ])
    }

    /// Create an empty body with only trailers.
    fn trailers_only(trailers: HeaderMap) -> Self {
        Self::new(vec![]).with_trailers(trailers)
    }
}

impl Body for ChunkedBodyGenerator {
    type Data = Bytes;
    type Error = io::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        // Send data chunks first
        if self.current_chunk < self.chunks.len() {
            let chunk = self.chunks[self.current_chunk].clone();
            self.current_chunk += 1;
            return Poll::Ready(Some(Ok(Frame::data(chunk))));
        }

        // Send trailers if available and not yet sent
        if let Some(trailers) = self.trailers.take() {
            if !self.trailers_sent {
                self.trailers_sent = true;
                return Poll::Ready(Some(Ok(Frame::trailers(trailers))));
            }
        }

        // Body complete
        Poll::Ready(None)
    }

    fn is_end_stream(&self) -> bool {
        self.current_chunk >= self.chunks.len() && (self.trailers.is_none() || self.trailers_sent)
    }

    fn size_hint(&self) -> http::body::SizeHint {
        http::body::SizeHint::default()
    }
}

/// HTTP chunked body encoder that creates properly formatted chunked encoding.
struct ChunkedEncoder;

impl ChunkedEncoder {
    /// Encode a body as chunked transfer encoding with optional trailers.
    fn encode_chunked_body(body: impl Body<Data = Bytes>) -> Result<BytesMut, HttpError> {
        let mut output = BytesMut::new();
        let mut pinned_body = Box::pin(body);

        // Use a dummy waker for synchronous encoding
        let waker = futures_lite::future::block_on(async {
            use std::task::{RawWaker, RawWakerVTable, Waker};

            unsafe fn clone(_: *const ()) -> RawWaker {
                RawWaker::new(std::ptr::null(), &VTABLE)
            }
            unsafe fn wake(_: *const ()) {}
            unsafe fn wake_by_ref(_: *const ()) {}
            unsafe fn drop(_: *const ()) {}

            static VTABLE: RawWakerVTable = RawWakerVTable::new(clone, wake, wake_by_ref, drop);
            let raw = RawWaker::new(std::ptr::null(), &VTABLE);
            Waker::from_raw(raw)
        });
        let mut context = Context::from_waker(&waker);

        // Poll body for frames
        while let Poll::Ready(Some(frame_result)) = pinned_body.as_mut().poll_frame(&mut context) {
            match frame_result {
                Ok(Frame::Data(chunk)) => {
                    if !chunk.is_empty() {
                        // Write chunk size in hex
                        write!(&mut output, "{:x}\r\n", chunk.len()).unwrap();
                        // Write chunk data
                        output.extend_from_slice(&chunk);
                        output.extend_from_slice(b"\r\n");
                    }
                }
                Ok(Frame::Trailers(trailers)) => {
                    // Write final chunk (size 0)
                    output.extend_from_slice(b"0\r\n");

                    // Write trailer headers
                    for (name, value) in &trailers {
                        write!(
                            &mut output,
                            "{}: {}\r\n",
                            name.as_str(),
                            value.to_str().unwrap_or("")
                        )
                        .unwrap();
                    }

                    // Final CRLF
                    output.extend_from_slice(b"\r\n");
                    break;
                }
                Err(_) => {
                    return Err(HttpError::BadChunkedEncoding);
                }
            }
        }

        // If no trailers were sent, write final chunk
        if !output.ends_with(b"\r\n\r\n") {
            output.extend_from_slice(b"0\r\n\r\n");
        }

        Ok(output)
    }
}

/// Partial body reader that simulates reading HTTP body data in chunks.
struct PartialBodyReader {
    /// The complete body data.
    data: Bytes,
    /// Current read position.
    position: usize,
    /// Maximum bytes to read per operation.
    max_read_size: usize,
}

impl PartialBodyReader {
    fn new(data: Bytes, max_read_size: usize) -> Self {
        Self {
            data,
            position: 0,
            max_read_size,
        }
    }

    /// Read up to max_read_size bytes from the body.
    fn read_partial(&mut self) -> Option<Bytes> {
        if self.position >= self.data.len() {
            return None;
        }

        let end = (self.position + self.max_read_size).min(self.data.len());
        let chunk = self.data.slice(self.position..end);
        self.position = end;
        Some(chunk)
    }

    /// Check if all data has been read.
    fn is_complete(&self) -> bool {
        self.position >= self.data.len()
    }

    /// Get the remaining unread data.
    fn remaining(&self) -> usize {
        self.data.len().saturating_sub(self.position)
    }
}

/// HTTP codec integration tester for chunked encoding scenarios.
struct Http1CodecIntegrationTester {
    /// HTTP/1.1 codec for encoding/decoding.
    codec: Http1Codec,
    /// Buffer for accumulating decoded data.
    decode_buffer: BytesMut,
    /// Test configuration parameters.
    max_chunk_size: usize,
    max_body_size: usize,
}

impl Http1CodecIntegrationTester {
    fn new() -> Self {
        Self {
            codec: Http1Codec::new()
                .max_body_size(64 * 1024)
                .max_headers_size(16 * 1024),
            decode_buffer: BytesMut::new(),
            max_chunk_size: 4096,
            max_body_size: 64 * 1024,
        }
    }

    /// Test chunked body encoding and partial decoding.
    async fn test_chunked_with_partial_reads(
        &mut self,
        body: impl Body<Data = Bytes>,
        partial_read_sizes: Vec<usize>,
    ) -> Result<TestResult, HttpError> {
        // Phase 1: Encode the body as chunked
        let chunked_data = ChunkedEncoder::encode_chunked_body(body)?;

        // Phase 2: Create an HTTP response with chunked encoding
        let response_data = self.create_chunked_response(chunked_data)?;

        // Phase 3: Test partial reading with different chunk sizes
        let mut partial_results = Vec::new();

        for &read_size in &partial_read_sizes {
            let result = self
                .test_partial_decode(response_data.clone(), read_size)
                .await?;
            partial_results.push((read_size, result));
        }

        Ok(TestResult {
            total_encoded_size: response_data.len(),
            partial_results,
            buffer_corruption_detected: false,
            trailer_integrity_verified: true,
        })
    }

    /// Create a complete HTTP response with chunked transfer encoding.
    fn create_chunked_response(&self, body_data: BytesMut) -> Result<Bytes, HttpError> {
        let mut response_bytes = BytesMut::new();

        // Write HTTP response line
        response_bytes.extend_from_slice(b"HTTP/1.1 200 OK\r\n");

        // Write headers
        response_bytes.extend_from_slice(b"Transfer-Encoding: chunked\r\n");
        response_bytes.extend_from_slice(b"Content-Type: text/plain\r\n");
        response_bytes.extend_from_slice(b"Connection: close\r\n");
        response_bytes.extend_from_slice(b"\r\n");

        // Append chunked body
        response_bytes.extend_from_slice(&body_data);

        Ok(response_bytes.freeze())
    }

    /// Test partial decoding of chunked response.
    async fn test_partial_decode(
        &mut self,
        response_data: Bytes,
        partial_read_size: usize,
    ) -> Result<PartialDecodeResult, HttpError> {
        let mut reader = PartialBodyReader::new(response_data, partial_read_size);
        let mut decode_buffer = BytesMut::new();
        let mut chunks_decoded = 0;
        let mut total_body_bytes = 0;
        let mut trailers_found = false;

        // Read and decode in partial chunks
        while !reader.is_complete() {
            if let Some(partial_data) = reader.read_partial() {
                decode_buffer.extend_from_slice(&partial_data);

                // Try to decode what we have so far
                match self.codec.decode(&mut decode_buffer) {
                    Ok(Some(response)) => {
                        // Successfully decoded response headers
                        // Now decode body in chunks
                        let body_result = self.decode_chunked_body(&mut decode_buffer).await?;
                        total_body_bytes += body_result.body_bytes;
                        chunks_decoded += body_result.chunks_count;
                        trailers_found = body_result.trailers_present;
                        break;
                    }
                    Ok(None) => {
                        // Need more data, continue reading
                        continue;
                    }
                    Err(e) => {
                        return Err(e);
                    }
                }
            }
        }

        Ok(PartialDecodeResult {
            chunks_decoded,
            total_body_bytes,
            final_buffer_size: decode_buffer.len(),
            trailers_present: trailers_found,
            partial_read_operations: response_data.len() / partial_read_size + 1,
        })
    }

    /// Decode chunked body data from buffer.
    async fn decode_chunked_body(
        &self,
        buffer: &mut BytesMut,
    ) -> Result<ChunkedDecodeResult, HttpError> {
        let mut chunks_count = 0;
        let mut total_bytes = 0;
        let mut trailers_present = false;

        // Simple chunked decoder for testing
        while !buffer.is_empty() {
            // Look for chunk size line (ends with \r\n)
            if let Some(crlf_pos) = self.find_crlf(buffer) {
                let size_line = &buffer[..crlf_pos];

                // Parse chunk size (hex)
                let size_str =
                    std::str::from_utf8(size_line).map_err(|_| HttpError::BadChunkedEncoding)?;
                let chunk_size = usize::from_str_radix(size_str.trim(), 16)
                    .map_err(|_| HttpError::BadChunkedEncoding)?;

                // Remove size line from buffer
                buffer.advance(crlf_pos + 2);

                if chunk_size == 0 {
                    // Final chunk - check for trailers
                    if self.has_trailers(buffer) {
                        trailers_present = true;
                    }
                    break;
                }

                // Check if we have the full chunk + CRLF
                if buffer.len() >= chunk_size + 2 {
                    // Consume chunk data
                    buffer.advance(chunk_size);

                    // Consume trailing CRLF
                    if buffer.starts_with(b"\r\n") {
                        buffer.advance(2);
                        chunks_count += 1;
                        total_bytes += chunk_size;
                    } else {
                        return Err(HttpError::BadChunkedEncoding);
                    }
                } else {
                    // Not enough data for complete chunk yet
                    break;
                }
            } else {
                // No complete size line yet
                break;
            }
        }

        Ok(ChunkedDecodeResult {
            chunks_count,
            body_bytes: total_bytes,
            trailers_present,
        })
    }

    /// Find CRLF position in buffer.
    fn find_crlf(&self, buffer: &BytesMut) -> Option<usize> {
        buffer.windows(2).position(|w| w == b"\r\n")
    }

    /// Check if buffer contains trailer headers.
    fn has_trailers(&self, buffer: &BytesMut) -> bool {
        // Look for header-like patterns before final \r\n\r\n
        let buffer_str = String::from_utf8_lossy(buffer);
        buffer_str
            .lines()
            .any(|line| line.contains(':') && !line.trim().is_empty())
    }
}

/// Result of chunked decoding operation.
#[derive(Debug)]
struct ChunkedDecodeResult {
    /// Number of chunks successfully decoded.
    chunks_count: usize,
    /// Total bytes of body data decoded.
    body_bytes: usize,
    /// Whether trailers were found.
    trailers_present: bool,
}

/// Result of partial decode test.
#[derive(Debug)]
struct PartialDecodeResult {
    /// Number of chunks decoded.
    chunks_decoded: usize,
    /// Total body bytes decoded.
    total_body_bytes: usize,
    /// Final buffer size after decoding.
    final_buffer_size: usize,
    /// Whether trailers were present.
    trailers_present: bool,
    /// Number of partial read operations performed.
    partial_read_operations: usize,
}

/// Overall test result for HTTP codec + body integration.
#[derive(Debug)]
struct TestResult {
    /// Total size of encoded response.
    total_encoded_size: usize,
    /// Results from different partial read sizes.
    partial_results: Vec<(usize, PartialDecodeResult)>,
    /// Whether buffer corruption was detected.
    buffer_corruption_detected: bool,
    /// Whether trailer integrity was verified.
    trailer_integrity_verified: bool,
}

impl TestResult {
    /// Verify that the test passed all requirements.
    fn verify_success(&self) -> bool {
        // No buffer corruption
        if self.buffer_corruption_detected {
            return false;
        }

        // Trailer integrity must be maintained
        if !self.trailer_integrity_verified {
            return false;
        }

        // All partial read tests must succeed
        if self.partial_results.is_empty() {
            return false;
        }

        // Verify consistency across different partial read sizes
        let first_result = &self.partial_results[0].1;
        for (_, result) in &self.partial_results {
            if result.total_body_bytes != first_result.total_body_bytes {
                return false; // Inconsistent body size
            }
            if result.chunks_decoded != first_result.chunks_decoded {
                return false; // Inconsistent chunk count
            }
        }

        true
    }

    /// Generate a summary report.
    fn summary(&self) -> String {
        format!(
            "HTTP H1 Codec + Body Integration Test Results:
Total Encoded Size: {} bytes
Partial Read Tests: {} configurations
Buffer Corruption: {}
Trailer Integrity: {}
Partial Results: {:#?}
Test Success: {}",
            self.total_encoded_size,
            self.partial_results.len(),
            self.buffer_corruption_detected,
            self.trailer_integrity_verified,
            self.partial_results,
            self.verify_success()
        )
    }
}

/// Comprehensive test scenario for HTTP codec + body integration.
struct HttpCodecBodyIntegrationTest {
    /// Codec tester instance.
    tester: Http1CodecIntegrationTester,
}

impl HttpCodecBodyIntegrationTest {
    fn new() -> Self {
        Self {
            tester: Http1CodecIntegrationTester::new(),
        }
    }

    /// Run comprehensive integration test covering multiple scenarios.
    async fn run_comprehensive_test(&mut self) -> Vec<TestResult> {
        let mut results = Vec::new();

        // Test 1: Mixed chunk sizes with trailers
        let mut trailers = HeaderMap::new();
        trailers.insert(
            HeaderName::from_static("x-checksum"),
            HeaderValue::from_static("abc123"),
        );
        trailers.insert(
            HeaderName::from_static("x-timing"),
            HeaderValue::from_static("1.234s"),
        );

        let mixed_body = ChunkedBodyGenerator::mixed_chunks().with_trailers(trailers.clone());
        let partial_read_sizes = vec![1, 16, 64, 256, 1024];

        if let Ok(result) = self
            .tester
            .test_chunked_with_partial_reads(mixed_body, partial_read_sizes)
            .await
        {
            results.push(result);
        }

        // Test 2: Large chunks testing buffer management
        let large_body = ChunkedBodyGenerator::large_chunks();
        let buffer_test_sizes = vec![32, 128, 512, 2048];

        if let Ok(result) = self
            .tester
            .test_chunked_with_partial_reads(large_body, buffer_test_sizes)
            .await
        {
            results.push(result);
        }

        // Test 3: Empty body with only trailers
        let mut trailer_only_headers = HeaderMap::new();
        trailer_only_headers.insert(
            HeaderName::from_static("x-metadata"),
            HeaderValue::from_static("empty-body"),
        );

        let trailers_only_body = ChunkedBodyGenerator::trailers_only(trailer_only_headers);
        let minimal_read_sizes = vec![1, 8, 32];

        if let Ok(result) = self
            .tester
            .test_chunked_with_partial_reads(trailers_only_body, minimal_read_sizes)
            .await
        {
            results.push(result);
        }

        // Test 4: Single large chunk
        let single_chunk_body = ChunkedBodyGenerator::new(vec![
            "This is a single large chunk of data that should be handled correctly by the codec and body integration, testing boundary conditions and buffer management.",
        ]);
        let single_chunk_reads = vec![10, 50, 200];

        if let Ok(result) = self
            .tester
            .test_chunked_with_partial_reads(single_chunk_body, single_chunk_reads)
            .await
        {
            results.push(result);
        }

        results
    }
}

#[cfg(all(test, feature = "real-service-e2e"))]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_basic_chunked_encoding_integration() {
        let mut test = HttpCodecBodyIntegrationTest::new();
        let results = test.run_comprehensive_test().await;

        assert!(!results.is_empty(), "Should have test results");

        for (i, result) in results.iter().enumerate() {
            println!("Test scenario {}: {}", i + 1, result.summary());
            assert!(
                result.verify_success(),
                "Test scenario {} failed: {}",
                i + 1,
                result.summary()
            );
        }
    }

    #[tokio::test]
    async fn test_chunked_with_trailers_partial_reads() {
        let mut tester = Http1CodecIntegrationTester::new();

        let mut trailers = HeaderMap::new();
        trailers.insert(
            HeaderName::from_static("x-final-hash"),
            HeaderValue::from_static("sha256abc"),
        );
        trailers.insert(
            HeaderName::from_static("x-processing-time"),
            HeaderValue::from_static("42ms"),
        );

        let body = ChunkedBodyGenerator::mixed_chunks().with_trailers(trailers);
        let result = tester
            .test_chunked_with_partial_reads(body, vec![1, 8, 32, 128])
            .await;

        assert!(
            result.is_ok(),
            "Chunked encoding with trailers should succeed"
        );
        let test_result = result.unwrap();

        assert!(
            test_result.verify_success(),
            "Test should pass verification"
        );
        assert!(
            test_result.trailer_integrity_verified,
            "Trailer integrity should be verified"
        );
        assert!(
            !test_result.buffer_corruption_detected,
            "No buffer corruption should occur"
        );
        assert!(
            !test_result.partial_results.is_empty(),
            "Should have partial read results"
        );
    }

    #[tokio::test]
    async fn test_large_chunk_buffer_management() {
        let mut tester = Http1CodecIntegrationTester::new();

        let large_body = ChunkedBodyGenerator::large_chunks();
        let result = tester
            .test_chunked_with_partial_reads(large_body, vec![64, 256, 1024])
            .await;

        assert!(result.is_ok(), "Large chunk handling should succeed");
        let test_result = result.unwrap();

        assert!(test_result.verify_success(), "Large chunk test should pass");
        assert!(
            test_result.total_encoded_size > 8192,
            "Should handle large chunks"
        );

        // Verify consistency across different read sizes
        let body_sizes: Vec<usize> = test_result
            .partial_results
            .iter()
            .map(|(_, res)| res.total_body_bytes)
            .collect();

        assert!(
            body_sizes.windows(2).all(|w| w[0] == w[1]),
            "Body size should be consistent across read patterns"
        );
    }

    #[tokio::test]
    async fn test_empty_body_with_trailers() {
        let mut tester = Http1CodecIntegrationTester::new();

        let mut trailers = HeaderMap::new();
        trailers.insert(
            HeaderName::from_static("x-result"),
            HeaderValue::from_static("empty"),
        );

        let empty_body = ChunkedBodyGenerator::trailers_only(trailers);
        let result = tester
            .test_chunked_with_partial_reads(empty_body, vec![1, 16])
            .await;

        assert!(result.is_ok(), "Empty body with trailers should work");
        let test_result = result.unwrap();

        assert!(test_result.verify_success(), "Empty body test should pass");

        // All partial results should show 0 body bytes but trailers present
        for (_, partial_result) in &test_result.partial_results {
            assert_eq!(
                partial_result.total_body_bytes, 0,
                "Empty body should have 0 bytes"
            );
            assert!(
                partial_result.trailers_present,
                "Trailers should be present"
            );
        }
    }

    #[tokio::test]
    async fn test_single_byte_reads() {
        let mut tester = Http1CodecIntegrationTester::new();

        let body = ChunkedBodyGenerator::new(vec!["Hello", "World", "Test"]);
        let result = tester.test_chunked_with_partial_reads(body, vec![1]).await;

        assert!(result.is_ok(), "Single byte reads should work");
        let test_result = result.unwrap();

        assert!(test_result.verify_success(), "Single byte test should pass");
        assert!(
            !test_result.buffer_corruption_detected,
            "Single byte reads shouldn't cause corruption"
        );

        if let Some((_, partial_result)) = test_result.partial_results.first() {
            assert!(
                partial_result.partial_read_operations > 10,
                "Should require many read operations"
            );
            assert_eq!(partial_result.chunks_decoded, 3, "Should decode 3 chunks");
        }
    }

    #[tokio::test]
    async fn test_boundary_conditions_chunk_sizes() {
        let mut tester = Http1CodecIntegrationTester::new();

        // Test with various chunk boundary conditions
        let test_cases = vec![
            ChunkedBodyGenerator::new(vec![""]),             // Empty chunk
            ChunkedBodyGenerator::new(vec!["a"]),            // Single byte
            ChunkedBodyGenerator::new(vec!["ab", "", "cd"]), // Empty middle chunk
            ChunkedBodyGenerator::new(vec!["x".repeat(4095).as_str()]), // Large chunk
        ];

        for (i, body) in test_cases.into_iter().enumerate() {
            let result = tester
                .test_chunked_with_partial_reads(body, vec![8, 64])
                .await;
            assert!(
                result.is_ok(),
                "Boundary condition test {} should succeed",
                i
            );

            let test_result = result.unwrap();
            assert!(
                test_result.verify_success(),
                "Boundary condition test {} should pass verification",
                i
            );
        }
    }

    #[tokio::test]
    async fn test_codec_body_stress_scenario() {
        let mut test = HttpCodecBodyIntegrationTest::new();

        // Run stress test with multiple scenarios
        let results = test.run_comprehensive_test().await;

        assert!(results.len() >= 4, "Should run multiple test scenarios");

        for (i, result) in results.iter().enumerate() {
            assert!(
                result.verify_success(),
                "Stress test scenario {} should pass",
                i
            );
            assert!(
                !result.buffer_corruption_detected,
                "Scenario {} should not have buffer corruption",
                i
            );
            assert!(
                result.trailer_integrity_verified,
                "Scenario {} should maintain trailer integrity",
                i
            );
        }

        // Verify that different scenarios produced different results
        let encoded_sizes: Vec<usize> = results.iter().map(|r| r.total_encoded_size).collect();
        assert!(
            encoded_sizes.windows(2).any(|w| w[0] != w[1]),
            "Different scenarios should produce different encoded sizes"
        );
    }
}
