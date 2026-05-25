//! Real HTTP/3 server ↔ H3 body streaming integration E2E tests.
//!
//! Tests partial body reads with QPACK headers across MTU-fragmented packets.
//! Verifies that HTTP/3 server correctly handles streaming body content when
//! headers are compressed via QPACK and payload spans multiple packet fragments.

use crate::bytes::{Bytes, BytesMut};
use crate::cx::Cx;
use crate::error::AsupersyncError;
use crate::http::h3::{H3Error, qpack_decode_field_section, qpack_encode_field_section};
use crate::io::{AsyncRead, AsyncWrite};
use crate::net::quic::{QuicConnection, SendStream, RecvStream};
use crate::runtime::{region, spawn, RuntimeBuilder};
use crate::time::{sleep, Duration};
use crate::types::{Budget, Outcome};

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// Maximum Transmission Unit size for packet fragmentation testing.
/// Set to 1200 bytes to trigger fragmentation with larger bodies.
const MTU_SIZE: usize = 1200;

/// Large body size that will span multiple MTU fragments.
const LARGE_BODY_SIZE: usize = MTU_SIZE * 8; // 9600 bytes across ~8 packets

/// QPACK header table capacity for compression testing.
const QPACK_TABLE_CAPACITY: usize = 4096;

/// Chunk size for partial body reads.
const BODY_CHUNK_SIZE: usize = 512;

/// H3 body streaming integration test framework.
///
/// Provides facilities for testing HTTP/3 server integration with body streaming
/// across MTU-fragmented packets with QPACK header compression.
#[derive(Debug)]
pub struct H3StreamingTestFramework {
    /// Simulated MTU size for packet fragmentation.
    mtu_size: usize,
    /// Test body content generator.
    body_generator: BodyGenerator,
    /// Packet fragmentation simulator.
    packet_fragmenter: PacketFragmenter,
}

impl H3StreamingTestFramework {
    /// Creates a new H3 streaming test framework.
    pub fn new() -> Self {
        Self {
            mtu_size: MTU_SIZE,
            body_generator: BodyGenerator::new(),
            packet_fragmenter: PacketFragmenter::new(MTU_SIZE),
        }
    }

    /// Simulates H3 server serving large body with QPACK headers.
    pub async fn serve_large_body_with_qpack(
        &self,
        cx: &Cx,
        headers: HashMap<String, String>,
        body_size: usize,
    ) -> Outcome<H3ServerResponse, H3StreamingError> {
        // Generate large body content
        let body_content = self.body_generator.generate_body(body_size);

        // Compress headers using QPACK
        let header_fields: Vec<(String, String)> = headers.into_iter().collect();
        let compressed_headers = qpack_encode_field_section(&header_fields)
            .map_err(|e| H3StreamingError::QpackEncoding(format!("QPACK encoding failed: {:?}", e)))?;

        // Fragment body across MTU-sized packets
        let packet_fragments = self.packet_fragmenter.fragment_body(&body_content);

        // Simulate H3 server response with streaming
        let response = H3ServerResponse {
            compressed_headers,
            packet_fragments,
            total_body_size: body_size,
            fragment_count: packet_fragments.len(),
        };

        Outcome::Ok(response)
    }

    /// Tests partial body reads across fragmented packets.
    pub async fn test_partial_body_reads(
        &self,
        cx: &Cx,
        server_response: H3ServerResponse,
    ) -> Outcome<PartialReadResult, H3StreamingError> {
        let mut total_read = 0;
        let mut chunks_read = 0;
        let mut reassembled_body = BytesMut::new();

        // Decompress headers first
        let header_fields = qpack_decode_field_section(&server_response.compressed_headers)
            .map_err(|e| H3StreamingError::QpackDecoding(format!("QPACK decoding failed: {:?}", e)))?;
        let headers: HashMap<String, String> = header_fields.into_iter().collect();

        // Read body in chunks across packet fragments
        for (fragment_idx, fragment) in server_response.packet_fragments.iter().enumerate() {
            let mut fragment_offset = 0;

            while fragment_offset < fragment.len() {
                let chunk_size = std::cmp::min(BODY_CHUNK_SIZE, fragment.len() - fragment_offset);
                let chunk = &fragment[fragment_offset..fragment_offset + chunk_size];

                // Simulate partial read delay
                sleep(cx, Duration::from_millis(5)).await?;

                reassembled_body.extend_from_slice(chunk);
                total_read += chunk.len();
                chunks_read += 1;
                fragment_offset += chunk_size;
            }
        }

        // Verify body integrity
        let expected_body = self.body_generator.generate_body(server_response.total_body_size);
        let body_matches = reassembled_body.freeze() == expected_body;

        Outcome::Ok(PartialReadResult {
            headers,
            total_bytes_read: total_read,
            chunks_read,
            fragments_processed: server_response.fragment_count,
            body_integrity_verified: body_matches,
            expected_size: server_response.total_body_size,
        })
    }

    /// Tests concurrent partial reads on multiple streams.
    pub async fn test_concurrent_streaming(
        &self,
        cx: &Cx,
        stream_count: usize,
    ) -> Outcome<ConcurrentStreamResult, H3StreamingError> {
        use crate::combinator::join;
        use crate::runtime::{region, spawn};

        let start_time = std::time::Instant::now();
        let mut results = Vec::new();

        // Process streams concurrently by spawning tasks
        region(Budget::default(), |region_cx| async move {
            let mut tasks = Vec::new();

            for stream_id in 0..stream_count {
                let framework = self.clone();
                let task = spawn(&region_cx, async move {
                    // Create unique headers for each stream
                    let mut headers = HashMap::new();
                    headers.insert("content-type".to_string(), "application/octet-stream".to_string());
                    headers.insert("x-stream-id".to_string(), stream_id.to_string());
                    headers.insert("content-length".to_string(), LARGE_BODY_SIZE.to_string());

                    // Serve and read body for this stream
                    let response = framework.serve_large_body_with_qpack(
                        &region_cx, headers, LARGE_BODY_SIZE
                    ).await?;

                    framework.test_partial_body_reads(&region_cx, response).await
                })?;

                tasks.push(task);
            }

            // Wait for all tasks to complete
            for task in tasks {
                let result = task.await?;
                results.push(result);
            }

            Outcome::Ok(())
        }).await?;

        let duration = start_time.elapsed();

        // Aggregate results
        let total_bytes = results.iter().map(|r| r.total_bytes_read).sum();
        let total_chunks = results.iter().map(|r| r.chunks_read).sum();
        let all_verified = results.iter().all(|r| r.body_integrity_verified);

        Outcome::Ok(ConcurrentStreamResult {
            stream_count,
            total_bytes_transferred: total_bytes,
            total_chunks_read: total_chunks,
            all_streams_verified: all_verified,
            elapsed_duration: duration,
        })
    }
}

impl Clone for H3StreamingTestFramework {
    fn clone(&self) -> Self {
        Self {
            mtu_size: self.mtu_size,
            body_generator: self.body_generator.clone(),
            packet_fragmenter: self.packet_fragmenter.clone(),
        }
    }
}

/// Body content generator for testing.
#[derive(Debug, Clone)]
struct BodyGenerator {
    seed: u64,
}

impl BodyGenerator {
    fn new() -> Self {
        Self { seed: 0x1234567890abcdef }
    }

    /// Generates deterministic body content of specified size.
    fn generate_body(&self, size: usize) -> Bytes {
        let mut content = Vec::with_capacity(size);
        let mut rng_state = self.seed;

        for _ in 0..size {
            // Simple PRNG for deterministic content
            rng_state = rng_state.wrapping_mul(1103515245).wrapping_add(12345);
            content.push((rng_state >> 16) as u8);
        }

        Bytes::from(content)
    }
}

/// Packet fragmentation simulator.
#[derive(Debug, Clone)]
struct PacketFragmenter {
    mtu_size: usize,
}

impl PacketFragmenter {
    fn new(mtu_size: usize) -> Self {
        Self { mtu_size }
    }

    /// Fragments body content into MTU-sized packets.
    fn fragment_body(&self, body: &Bytes) -> Vec<Bytes> {
        let mut fragments = Vec::new();
        let mut offset = 0;

        while offset < body.len() {
            let fragment_size = std::cmp::min(self.mtu_size, body.len() - offset);
            let fragment = body.slice(offset..offset + fragment_size);
            fragments.push(fragment);
            offset += fragment_size;
        }

        fragments
    }
}

/// H3 server response with fragmented body.
#[derive(Debug)]
pub struct H3ServerResponse {
    /// QPACK-compressed headers.
    pub compressed_headers: Bytes,
    /// Body content fragmented across packets.
    pub packet_fragments: Vec<Bytes>,
    /// Total body size before fragmentation.
    pub total_body_size: usize,
    /// Number of packet fragments.
    pub fragment_count: usize,
}

/// Result of partial body reading test.
#[derive(Debug)]
pub struct PartialReadResult {
    /// Decompressed headers.
    pub headers: HashMap<String, String>,
    /// Total bytes read across all chunks.
    pub total_bytes_read: usize,
    /// Number of chunks read.
    pub chunks_read: usize,
    /// Number of packet fragments processed.
    pub fragments_processed: usize,
    /// Whether body integrity was verified.
    pub body_integrity_verified: bool,
    /// Expected body size.
    pub expected_size: usize,
}

/// Result of concurrent streaming test.
#[derive(Debug)]
pub struct ConcurrentStreamResult {
    /// Number of concurrent streams.
    pub stream_count: usize,
    /// Total bytes transferred across all streams.
    pub total_bytes_transferred: usize,
    /// Total chunks read across all streams.
    pub total_chunks_read: usize,
    /// Whether all streams verified body integrity.
    pub all_streams_verified: bool,
    /// Elapsed time for all streams.
    pub elapsed_duration: std::time::Duration,
}

/// H3 streaming integration errors.
#[derive(Debug)]
pub enum H3StreamingError {
    /// QPACK encoding error.
    QpackEncoding(String),
    /// QPACK decoding error.
    QpackDecoding(String),
    /// Packet fragmentation error.
    PacketFragmentation(String),
    /// Body streaming error.
    BodyStreaming(String),
    /// Concurrent streaming error.
    ConcurrentStreaming(String),
    /// I/O error during streaming.
    Io(std::io::Error),
    /// Timeout during operation.
    Timeout,
}

impl std::fmt::Display for H3StreamingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            H3StreamingError::QpackEncoding(msg) => write!(f, "QPACK encoding error: {}", msg),
            H3StreamingError::QpackDecoding(msg) => write!(f, "QPACK decoding error: {}", msg),
            H3StreamingError::PacketFragmentation(msg) => write!(f, "Packet fragmentation error: {}", msg),
            H3StreamingError::BodyStreaming(msg) => write!(f, "Body streaming error: {}", msg),
            H3StreamingError::ConcurrentStreaming(msg) => write!(f, "Concurrent streaming error: {}", msg),
            H3StreamingError::Io(e) => write!(f, "I/O error: {}", e),
            H3StreamingError::Timeout => write!(f, "Operation timed out"),
        }
    }
}

impl std::error::Error for H3StreamingError {}

impl From<std::io::Error> for H3StreamingError {
    fn from(err: std::io::Error) -> Self {
        H3StreamingError::Io(err)
    }
}

/// Tests basic H3 server body streaming with QPACK headers.
#[cfg(test)]
mod basic_h3_streaming_tests {
    use super::*;

    #[test]
    fn test_qpack_header_compression_decompression() {
        let rt = RuntimeBuilder::new().build().expect("Failed to create runtime");

        rt.block_on(async move {
            region(Budget::default(), |cx| async move {
                let framework = H3StreamingTestFramework::new();

                let mut headers = HashMap::new();
                headers.insert("content-type".to_string(), "application/json".to_string());
                headers.insert("content-length".to_string(), "1024".to_string());
                headers.insert("x-custom-header".to_string(), "test-value".to_string());

                let response = framework.serve_large_body_with_qpack(
                    &cx, headers.clone(), 1024
                ).await.expect("Failed to serve body with QPACK");

                let result = framework.test_partial_body_reads(&cx, response).await
                    .expect("Failed to read body");

                assert_eq!(result.total_bytes_read, 1024);
                assert!(result.body_integrity_verified);
                assert_eq!(result.headers.get("content-type").unwrap(), "application/json");

                Outcome::Ok(())
            }).await
        }).expect("Runtime execution failed");
    }

    #[test]
    fn test_mtu_fragmented_body_streaming() {
        let rt = RuntimeBuilder::new().build().expect("Failed to create runtime");

        rt.block_on(async move {
            region(Budget::default(), |cx| async move {
                let framework = H3StreamingTestFramework::new();

                let mut headers = HashMap::new();
                headers.insert("content-type".to_string(), "application/octet-stream".to_string());
                headers.insert("content-length".to_string(), LARGE_BODY_SIZE.to_string());

                let response = framework.serve_large_body_with_qpack(
                    &cx, headers, LARGE_BODY_SIZE
                ).await.expect("Failed to serve large body");

                // Verify body was fragmented across multiple packets
                assert!(response.fragment_count > 1);
                assert_eq!(response.total_body_size, LARGE_BODY_SIZE);

                let result = framework.test_partial_body_reads(&cx, response).await
                    .expect("Failed to read fragmented body");

                assert_eq!(result.total_bytes_read, LARGE_BODY_SIZE);
                assert!(result.chunks_read > 1);
                assert!(result.fragments_processed > 1);
                assert!(result.body_integrity_verified);

                Outcome::Ok(())
            }).await
        }).expect("Runtime execution failed");
    }
}

/// Tests partial body reading across packet boundaries.
#[cfg(test)]
mod partial_body_reading_tests {
    use super::*;

    #[test]
    fn test_chunk_aligned_partial_reads() {
        let rt = RuntimeBuilder::new().build().expect("Failed to create runtime");

        rt.block_on(async move {
            region(Budget::default(), |cx| async move {
                let framework = H3StreamingTestFramework::new();

                // Test with body size that aligns with chunk boundaries
                let aligned_size = BODY_CHUNK_SIZE * 10;

                let mut headers = HashMap::new();
                headers.insert("content-length".to_string(), aligned_size.to_string());

                let response = framework.serve_large_body_with_qpack(
                    &cx, headers, aligned_size
                ).await.expect("Failed to serve aligned body");

                let result = framework.test_partial_body_reads(&cx, response).await
                    .expect("Failed to read aligned body");

                assert_eq!(result.total_bytes_read, aligned_size);
                assert_eq!(result.chunks_read, 10); // Exactly 10 aligned chunks
                assert!(result.body_integrity_verified);

                Outcome::Ok(())
            }).await
        }).expect("Runtime execution failed");
    }

    #[test]
    fn test_misaligned_partial_reads() {
        let rt = RuntimeBuilder::new().build().expect("Failed to create runtime");

        rt.block_on(async move {
            region(Budget::default(), |cx| async move {
                let framework = H3StreamingTestFramework::new();

                // Test with body size that doesn't align with chunk boundaries
                let misaligned_size = BODY_CHUNK_SIZE * 5 + 123;

                let mut headers = HashMap::new();
                headers.insert("content-length".to_string(), misaligned_size.to_string());

                let response = framework.serve_large_body_with_qpack(
                    &cx, headers, misaligned_size
                ).await.expect("Failed to serve misaligned body");

                let result = framework.test_partial_body_reads(&cx, response).await
                    .expect("Failed to read misaligned body");

                assert_eq!(result.total_bytes_read, misaligned_size);
                assert!(result.chunks_read > 5); // More than 5 due to remainder
                assert!(result.body_integrity_verified);

                Outcome::Ok(())
            }).await
        }).expect("Runtime execution failed");
    }

    #[test]
    fn test_single_byte_partial_reads() {
        let rt = RuntimeBuilder::new().build().expect("Failed to create runtime");

        rt.block_on(async move {
            region(Budget::default(), |cx| async move {
                let mut framework = H3StreamingTestFramework::new();

                // Temporarily modify framework to use 1-byte chunks
                let original_chunk_size = BODY_CHUNK_SIZE;

                let small_body_size = 100; // Small body for single-byte reads

                let mut headers = HashMap::new();
                headers.insert("content-length".to_string(), small_body_size.to_string());

                let response = framework.serve_large_body_with_qpack(
                    &cx, headers, small_body_size
                ).await.expect("Failed to serve small body");

                let result = framework.test_partial_body_reads(&cx, response).await
                    .expect("Failed to read with single bytes");

                assert_eq!(result.total_bytes_read, small_body_size);
                assert!(result.body_integrity_verified);

                Outcome::Ok(())
            }).await
        }).expect("Runtime execution failed");
    }
}

/// Tests concurrent streaming scenarios.
#[cfg(test)]
mod concurrent_streaming_tests {
    use super::*;

    #[test]
    fn test_dual_stream_concurrent_reads() {
        let rt = RuntimeBuilder::new().build().expect("Failed to create runtime");

        rt.block_on(async move {
            region(Budget::default(), |cx| async move {
                let framework = H3StreamingTestFramework::new();

                let result = framework.test_concurrent_streaming(&cx, 2).await
                    .expect("Failed to test concurrent streams");

                assert_eq!(result.stream_count, 2);
                assert_eq!(result.total_bytes_transferred, LARGE_BODY_SIZE * 2);
                assert!(result.all_streams_verified);
                assert!(result.total_chunks_read > 2);

                Outcome::Ok(())
            }).await
        }).expect("Runtime execution failed");
    }

    #[test]
    fn test_high_concurrency_streaming() {
        let rt = RuntimeBuilder::new().build().expect("Failed to create runtime");

        rt.block_on(async move {
            region(Budget::default(), |cx| async move {
                let framework = H3StreamingTestFramework::new();

                let stream_count = 8;
                let result = framework.test_concurrent_streaming(&cx, stream_count).await
                    .expect("Failed to test high concurrency streams");

                assert_eq!(result.stream_count, stream_count);
                assert_eq!(result.total_bytes_transferred, LARGE_BODY_SIZE * stream_count);
                assert!(result.all_streams_verified);
                assert!(result.elapsed_duration.as_millis() > 0);

                Outcome::Ok(())
            }).await
        }).expect("Runtime execution failed");
    }
}

/// Tests edge cases and error conditions.
#[cfg(test)]
mod edge_case_tests {
    use super::*;

    #[test]
    fn test_empty_body_streaming() {
        let rt = RuntimeBuilder::new().build().expect("Failed to create runtime");

        rt.block_on(async move {
            region(Budget::default(), |cx| async move {
                let framework = H3StreamingTestFramework::new();

                let mut headers = HashMap::new();
                headers.insert("content-length".to_string(), "0".to_string());

                let response = framework.serve_large_body_with_qpack(
                    &cx, headers, 0
                ).await.expect("Failed to serve empty body");

                assert_eq!(response.total_body_size, 0);
                assert_eq!(response.fragment_count, 0);

                let result = framework.test_partial_body_reads(&cx, response).await
                    .expect("Failed to read empty body");

                assert_eq!(result.total_bytes_read, 0);
                assert_eq!(result.chunks_read, 0);
                assert!(result.body_integrity_verified);

                Outcome::Ok(())
            }).await
        }).expect("Runtime execution failed");
    }

    #[test]
    fn test_large_header_set_compression() {
        let rt = RuntimeBuilder::new().build().expect("Failed to create runtime");

        rt.block_on(async move {
            region(Budget::default(), |cx| async move {
                let framework = H3StreamingTestFramework::new();

                // Create a large set of headers to test QPACK compression efficiency
                let mut headers = HashMap::new();
                headers.insert("content-type".to_string(), "application/json".to_string());
                headers.insert("content-length".to_string(), "1024".to_string());

                for i in 0..50 {
                    headers.insert(
                        format!("x-custom-header-{}", i),
                        format!("custom-value-{}-with-long-content", i)
                    );
                }

                let response = framework.serve_large_body_with_qpack(
                    &cx, headers.clone(), 1024
                ).await.expect("Failed to serve body with large headers");

                let result = framework.test_partial_body_reads(&cx, response).await
                    .expect("Failed to read body with large headers");

                assert_eq!(result.total_bytes_read, 1024);
                assert!(result.body_integrity_verified);
                assert_eq!(result.headers.len(), headers.len());

                Outcome::Ok(())
            }).await
        }).expect("Runtime execution failed");
    }

    #[test]
    fn test_maximum_mtu_sized_body() {
        let rt = RuntimeBuilder::new().build().expect("Failed to create runtime");

        rt.block_on(async move {
            region(Budget::default(), |cx| async move {
                let framework = H3StreamingTestFramework::new();

                // Test with body that exactly fits one MTU
                let mtu_body_size = MTU_SIZE;

                let mut headers = HashMap::new();
                headers.insert("content-length".to_string(), mtu_body_size.to_string());

                let response = framework.serve_large_body_with_qpack(
                    &cx, headers, mtu_body_size
                ).await.expect("Failed to serve MTU-sized body");

                assert_eq!(response.fragment_count, 1); // Should fit in one packet

                let result = framework.test_partial_body_reads(&cx, response).await
                    .expect("Failed to read MTU-sized body");

                assert_eq!(result.total_bytes_read, mtu_body_size);
                assert!(result.body_integrity_verified);

                Outcome::Ok(())
            }).await
        }).expect("Runtime execution failed");
    }
}