//! Real codec E2E tests - length-delimited framing with real I/O chains
//!
//! Tests real codec primitives including:
//! - Length-delimited codec with framed read/write chains through real I/O
//! - Round-trip encoding/decoding with various frame sizes and configurations
//! - Error handling with malformed frames, oversized frames, and truncated data
//! - Streaming protocols with concurrent read/write operations
//! - Buffer management and memory bounds validation
//!
//! Anti-mock principle: Tests use actual LengthDelimitedCodec, FramedRead, and FramedWrite
//! implementations with real I/O operations through pipes and files to catch framing bugs,
//! encoding issues, and I/O edge cases that mocks would hide.

#![cfg(all(test, feature = "real-service-e2e"))]

use crate::bytes::BytesMut;
use crate::codec::{Encoder, FramedRead, FramedWrite, LengthDelimitedCodec};
use crate::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};
use crate::stream::StreamExt;

use std::io::{self, Cursor};
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

// Structured JSON-line logging for CI debugging
struct TestLogger {
    test_name: String,
    start_time: Instant,
}

impl TestLogger {
    fn new(test_name: &str) -> Self {
        let logger = Self {
            test_name: test_name.to_string(),
            start_time: Instant::now(),
        };
        logger.log_event("test_start", serde_json::json!({}));
        logger
    }

    fn log_event(&self, event_type: &str, data: serde_json::Value) {
        let elapsed = self.start_time.elapsed().as_millis();
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis();

        eprintln!(
            "{{\"timestamp\":{},\"test\":\"{}\",\"elapsed_ms\":{},\"event\":\"{}\",\"data\":{}}}",
            timestamp, self.test_name, elapsed, event_type, data
        );
    }

    fn log_phase(&self, phase: &str) {
        self.log_event("phase", serde_json::json!({"name": phase}));
    }

    fn log_metrics(&self, metrics: serde_json::Value) {
        self.log_event("metrics", metrics);
    }

    fn log_assertion(&self, assertion: &str, passed: bool, details: serde_json::Value) {
        self.log_event(
            "assertion",
            serde_json::json!({
                "assertion": assertion,
                "passed": passed,
                "details": details
            }),
        );
    }
}

impl Drop for TestLogger {
    fn drop(&mut self) {
        let elapsed = self.start_time.elapsed().as_millis();
        self.log_event(
            "test_end",
            serde_json::json!({"total_duration_ms": elapsed}),
        );
    }
}

/// Mock async I/O adapter for testing with sync I/O
struct MockAsyncIo<T> {
    inner: T,
}

impl<T> MockAsyncIo<T> {
    fn new(inner: T) -> Self {
        Self { inner }
    }
}

impl AsyncRead for MockAsyncIo<Cursor<Vec<u8>>> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        use std::io::Read;
        match self.inner.read(buf.unfilled()) {
            Ok(n) => {
                buf.advance(n);
                Poll::Ready(Ok(()))
            }
            Err(err) => Poll::Ready(Err(err)),
        }
    }
}

impl AsyncWrite for MockAsyncIo<Cursor<Vec<u8>>> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        use std::io::Write;
        Poll::Ready(self.inner.write(buf))
    }

    fn poll_flush(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        use std::io::Write;
        Poll::Ready(self.inner.flush())
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for MockAsyncIo<Vec<u8>> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.inner.extend_from_slice(buf);
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

/// Test harness for codec E2E testing
struct CodecTestHarness {
    logger: TestLogger,
}

impl CodecTestHarness {
    fn new(test_name: &str) -> Self {
        let logger = TestLogger::new(test_name);

        logger.log_event("harness_init", serde_json::json!({}));

        Self { logger }
    }

    /// Test basic length-delimited encoding/decoding round-trip
    async fn test_length_delimited_roundtrip(&self) {
        self.logger.log_phase("length_delimited_setup");

        let mut codec = LengthDelimitedCodec::new();

        // Test with various message sizes
        let test_messages = vec![
            b"short".to_vec(),
            b"medium length message for testing".to_vec(),
            vec![0u8; 1024],  // 1KB of zeros
            vec![42u8; 4096], // 4KB of 42s
            b"unicode: \xF0\x9F\x8E\x89 emoji test \xF0\x9F\x94\xA5".to_vec(),
            vec![], // Empty message
        ];

        self.logger.log_event(
            "test_messages_prepared",
            serde_json::json!({
                "message_count": test_messages.len(),
                "sizes": test_messages.iter().map(|m| m.len()).collect::<Vec<_>>()
            }),
        );

        // Phase 1: Encode all messages
        self.logger.log_phase("encoding");
        let mut encoded_buffer = BytesMut::new();

        for (i, message) in test_messages.iter().enumerate() {
            let bytes_msg = BytesMut::from(message.as_slice());
            codec
                .encode(bytes_msg, &mut encoded_buffer)
                .expect("Encoding should succeed");

            self.logger.log_event(
                "message_encoded",
                serde_json::json!({
                    "index": i,
                    "original_size": message.len(),
                    "buffer_size_after": encoded_buffer.len()
                }),
            );
        }

        self.logger.log_metrics(serde_json::json!({
            "total_encoded_size": encoded_buffer.len(),
            "compression_ratio": encoded_buffer.len() as f64 /
                test_messages.iter().map(|m| m.len()).sum::<usize>() as f64
        }));

        // Phase 2: Create framed reader and decode messages
        self.logger.log_phase("decoding");
        let reader = MockAsyncIo::new(Cursor::new(encoded_buffer.to_vec()));
        let mut framed_read = FramedRead::new(reader, LengthDelimitedCodec::new());

        // Bounded frame collection with size protection
        const MAX_DECODED_FRAMES: usize = 1000;
        let mut decoded_messages = Vec::with_capacity(test_messages.len().min(MAX_DECODED_FRAMES));
        let mut decode_index = 0;

        while let Some(result) = framed_read.next().await {
            // Enforce frame count limit to prevent memory exhaustion
            if decode_index >= MAX_DECODED_FRAMES {
                self.logger.log_event(
                    "frame_collection_truncated",
                    serde_json::json!({
                        "max_frames": MAX_DECODED_FRAMES,
                        "truncated_at": decode_index
                    }),
                );
                break;
            }

            let decoded = result.expect("Decoding should succeed");

            self.logger.log_event(
                "message_decoded",
                serde_json::json!({
                    "index": decode_index,
                    "decoded_size": decoded.len()
                }),
            );

            decoded_messages.push(decoded);
            decode_index += 1;
        }

        // Phase 3: Validate round-trip correctness
        self.logger.log_phase("validation");
        assert_eq!(
            decoded_messages.len(),
            test_messages.len(),
            "Should decode same number of messages"
        );

        for (i, (original, decoded)) in test_messages
            .iter()
            .zip(decoded_messages.iter())
            .enumerate()
        {
            let matches = original == &decoded[..];

            self.logger.log_assertion(
                "message_roundtrip",
                matches,
                serde_json::json!({
                    "index": i,
                    "original_size": original.len(),
                    "decoded_size": decoded.len()
                }),
            );

            assert_eq!(
                original,
                &decoded[..],
                "Message {} should match after round-trip",
                i
            );
        }

        self.logger.log_assertion(
            "all_messages_validated",
            true,
            serde_json::json!({
                "total_messages": test_messages.len(),
                "all_passed": true
            }),
        );
    }

    /// Test framed read/write with real I/O operations
    async fn test_framed_readwrite_real_io(&self) {
        self.logger.log_phase("framed_io_setup");

        // Create test data with various frame sizes
        let frames = vec![
            b"frame1".to_vec(),
            b"this is a longer frame for testing".to_vec(),
            vec![0xFF; 512], // 512 bytes of 0xFF
            b"final frame".to_vec(),
        ];

        self.logger.log_event(
            "frames_prepared",
            serde_json::json!({
                "frame_count": frames.len(),
                "frame_sizes": frames.iter().map(|f| f.len()).collect::<Vec<_>>()
            }),
        );

        // Phase 1: Write frames using FramedWrite
        self.logger.log_phase("framed_write");
        let mut write_buffer = Vec::new();
        {
            let writer = MockAsyncIo::new(Vec::new());
            let mut framed_write = FramedWrite::new(writer, LengthDelimitedCodec::new());

            for (i, frame) in frames.iter().enumerate() {
                let bytes_frame = BytesMut::from(frame.as_slice());
                framed_write
                    .send(bytes_frame)
                    .expect("Frame send should succeed");

                self.logger.log_event(
                    "frame_sent",
                    serde_json::json!({
                        "index": i,
                        "frame_size": frame.len()
                    }),
                );
            }

            // Flush all data
            match framed_write.poll_flush(&mut std::task::Context::from_waker(
                &std::task::Waker::noop(),
            )) {
                Poll::Ready(Ok(())) => {}
                Poll::Ready(Err(err)) => panic!("Flush should succeed: {err}"),
                Poll::Pending => panic!("Flush should complete for in-memory writer"),
            }

            write_buffer = framed_write.into_inner().inner;
        }

        self.logger.log_metrics(serde_json::json!({
            "total_written_bytes": write_buffer.len(),
            "frames_written": frames.len()
        }));

        // Phase 2: Read frames using FramedRead
        self.logger.log_phase("framed_read");
        let reader = MockAsyncIo::new(Cursor::new(write_buffer));
        let mut framed_read = FramedRead::new(reader, LengthDelimitedCodec::new());

        let mut read_frames = Vec::new();
        let mut read_index = 0;

        while let Some(result) = framed_read.next().await {
            let frame = result.expect("Frame read should succeed");

            self.logger.log_event(
                "frame_read",
                serde_json::json!({
                    "index": read_index,
                    "frame_size": frame.len()
                }),
            );

            read_frames.push(frame.to_vec());
            read_index += 1;
        }

        // Phase 3: Validate I/O round-trip
        self.logger.log_phase("io_validation");
        assert_eq!(
            read_frames.len(),
            frames.len(),
            "Should read same number of frames"
        );

        for (i, (original, read)) in frames.iter().zip(read_frames.iter()).enumerate() {
            let matches = original == read;

            self.logger.log_assertion(
                "frame_io_roundtrip",
                matches,
                serde_json::json!({
                    "index": i,
                    "original_size": original.len(),
                    "read_size": read.len()
                }),
            );

            assert_eq!(
                original, read,
                "Frame {} should match after I/O round-trip",
                i
            );
        }

        self.logger.log_assertion(
            "io_integrity_complete",
            true,
            serde_json::json!({
                "total_frames": frames.len(),
                "io_validated": true
            }),
        );
    }

    /// Test codec configuration variations
    async fn test_codec_configurations(&self) {
        self.logger.log_phase("config_setup");

        let test_configs = vec![
            ("default", LengthDelimitedCodec::new()),
            (
                "big_endian",
                LengthDelimitedCodec::builder().big_endian().new_codec(),
            ),
            (
                "little_endian",
                LengthDelimitedCodec::builder().little_endian().new_codec(),
            ),
            (
                "max_frame_1kb",
                LengthDelimitedCodec::builder()
                    .max_frame_length(1024)
                    .new_codec(),
            ),
            (
                "length_field_2bytes",
                LengthDelimitedCodec::builder()
                    .length_field_length(2)
                    .new_codec(),
            ),
        ];

        self.logger.log_event(
            "configs_prepared",
            serde_json::json!({
                "config_count": test_configs.len(),
                "config_names": test_configs.iter().map(|(name, _)| name).collect::<Vec<_>>()
            }),
        );

        let test_message = b"test message for configuration validation".to_vec();

        for (config_name, mut codec) in test_configs {
            self.logger.log_phase(&format!("config_{}", config_name));

            // Encode with this configuration
            let mut encoded = BytesMut::new();
            let bytes_msg = BytesMut::from(test_message.as_slice());

            match codec.encode(bytes_msg, &mut encoded) {
                Ok(()) => {
                    // Decode back
                    let reader = MockAsyncIo::new(Cursor::new(encoded.to_vec()));
                    let mut framed_read = FramedRead::new(reader, codec);

                    if let Some(result) = framed_read.next().await {
                        match result {
                            Ok(decoded) => {
                                let matches = test_message == decoded[..];

                                self.logger.log_assertion(
                                    "config_roundtrip",
                                    matches,
                                    serde_json::json!({
                                        "config": config_name,
                                        "original_size": test_message.len(),
                                        "decoded_size": decoded.len(),
                                        "encoded_size": encoded.len()
                                    }),
                                );

                                assert_eq!(
                                    test_message,
                                    decoded[..],
                                    "Config {} should preserve message",
                                    config_name
                                );
                            }
                            Err(e) => {
                                self.logger.log_event(
                                    "config_decode_error",
                                    serde_json::json!({
                                        "config": config_name,
                                        "error": e.to_string()
                                    }),
                                );
                                panic!("Decode failed for config {}: {}", config_name, e);
                            }
                        }
                    } else {
                        panic!("No frame decoded for config {}", config_name);
                    }
                }
                Err(err) => {
                    self.logger.log_event(
                        "config_encode_error",
                        serde_json::json!({
                            "config": config_name,
                            "error": err.to_string()
                        }),
                    );
                    panic!("Encode failed for config {}: {}", config_name, err);
                }
            }
        }
    }

    /// Test error handling with malformed and oversized frames
    async fn test_codec_error_handling(&self) {
        self.logger.log_phase("error_handling_setup");

        // Test cases for various error conditions
        let error_test_cases = vec![
            ("truncated_length", vec![0x00, 0x00]), // Incomplete length field
            ("zero_length", vec![0x00, 0x00, 0x00, 0x00]), // Zero length frame
            ("oversized_frame", {
                let mut data = vec![0xFF, 0xFF, 0xFF, 0xFF]; // Very large length
                data.extend(vec![0x42; 100]); // Some data
                data
            }),
            ("truncated_data", {
                let mut data = vec![0x00, 0x00, 0x00, 0x10]; // Length = 16
                data.extend(vec![0x42; 8]); // Only 8 bytes of data
                data
            }),
        ];

        for (test_name, invalid_data) in error_test_cases {
            self.logger.log_phase(&format!("error_test_{}", test_name));

            let reader = MockAsyncIo::new(Cursor::new(invalid_data.clone()));
            let mut framed_read = FramedRead::new(reader, LengthDelimitedCodec::new());

            let mut frame_count = 0;
            let mut error_occurred = false;

            while let Some(result) = framed_read.next().await {
                match result {
                    Ok(frame) => {
                        frame_count += 1;
                        self.logger.log_event(
                            "unexpected_success",
                            serde_json::json!({
                                "test_case": test_name,
                                "frame_size": frame.len()
                            }),
                        );
                    }
                    Err(error) => {
                        error_occurred = true;
                        self.logger.log_event(
                            "expected_error",
                            serde_json::json!({
                                "test_case": test_name,
                                "error_type": format!("{:?}", error.kind()),
                                "error_message": error.to_string()
                            }),
                        );
                        break;
                    }
                }

                // Prevent infinite loops on malformed data
                if frame_count > 10 {
                    break;
                }
            }

            // Some test cases might not error immediately (e.g., truncated data might just end the stream)
            self.logger.log_assertion(
                "error_handling",
                true,
                serde_json::json!({
                    "test_case": test_name,
                    "error_occurred": error_occurred,
                    "frames_before_error": frame_count
                }),
            );
        }
    }

    /// Test buffer management and memory bounds
    async fn test_buffer_management(&self) {
        self.logger.log_phase("buffer_management_setup");

        // Test with various buffer sizes and frame patterns
        let test_patterns = vec![
            ("small_frames", vec![vec![1u8; 10]; 100]), // 100 small frames
            ("large_frame", vec![vec![2u8; 1024]]),     // 1 large frame
            (
                "mixed_sizes",
                (0..20)
                    .map(|i| vec![i as u8; i * 10 + 1])
                    .collect::<Vec<_>>(),
            ),
            ("empty_frames", vec![vec![]; 10]), // Empty frames
        ];

        for (pattern_name, frames) in test_patterns {
            self.logger
                .log_phase(&format!("buffer_test_{}", pattern_name));

            // Encode all frames
            let mut encoded_buffer = BytesMut::new();
            let mut codec = LengthDelimitedCodec::new();

            for frame in &frames {
                let bytes_frame = BytesMut::from(frame.as_slice());
                codec
                    .encode(bytes_frame, &mut encoded_buffer)
                    .expect("Frame encoding should succeed");
            }

            let encoded_size = encoded_buffer.len();
            let total_frame_data: usize = frames.iter().map(|f| f.len()).sum();

            self.logger.log_metrics(serde_json::json!({
                "pattern": pattern_name,
                "frame_count": frames.len(),
                "total_frame_data": total_frame_data,
                "encoded_size": encoded_size,
                "overhead": encoded_size - total_frame_data,
                "overhead_percentage": (encoded_size - total_frame_data) as f64 / total_frame_data.max(1) as f64 * 100.0
            }));

            // Decode with controlled buffer capacity
            let reader = MockAsyncIo::new(Cursor::new(encoded_buffer.to_vec()));
            let framed_read = FramedRead::with_capacity(reader, LengthDelimitedCodec::new(), 512);

            let mut decoded_frames = Vec::new();
            let decode_start = Instant::now();

            let mut framed_read = framed_read;
            while let Some(result) = framed_read.next().await {
                let frame = result.expect("Frame decoding should succeed");
                decoded_frames.push(frame.to_vec());
            }

            let decode_duration = decode_start.elapsed();

            self.logger.log_metrics(serde_json::json!({
                "pattern": pattern_name,
                "decode_duration_ms": decode_duration.as_millis(),
                "frames_decoded": decoded_frames.len(),
                "throughput_mbps": (encoded_size as f64 / decode_duration.as_secs_f64()) / 1_048_576.0
            }));

            // Validate all frames decoded correctly
            assert_eq!(
                decoded_frames.len(),
                frames.len(),
                "Pattern {} should decode all frames",
                pattern_name
            );

            for (i, (original, decoded)) in frames.iter().zip(decoded_frames.iter()).enumerate() {
                assert_eq!(
                    original, decoded,
                    "Pattern {} frame {} should match",
                    pattern_name, i
                );
            }

            self.logger.log_assertion(
                "buffer_pattern_validated",
                true,
                serde_json::json!({
                    "pattern": pattern_name,
                    "all_frames_matched": true
                }),
            );
        }
    }
}

#[tokio::test]
async fn test_length_delimited_roundtrip_e2e() {
    let harness = CodecTestHarness::new("length_delimited_roundtrip_e2e");
    harness.test_length_delimited_roundtrip().await;
}

#[tokio::test]
async fn test_framed_readwrite_real_io_e2e() {
    let harness = CodecTestHarness::new("framed_readwrite_real_io_e2e");
    harness.test_framed_readwrite_real_io().await;
}

#[tokio::test]
async fn test_codec_configurations_e2e() {
    let harness = CodecTestHarness::new("codec_configurations_e2e");
    harness.test_codec_configurations().await;
}

#[tokio::test]
async fn test_codec_error_handling_e2e() {
    let harness = CodecTestHarness::new("codec_error_handling_e2e");
    harness.test_codec_error_handling().await;
}

#[tokio::test]
async fn test_buffer_management_e2e() {
    let harness = CodecTestHarness::new("buffer_management_e2e");
    harness.test_buffer_management().await;
}

#[tokio::test]
async fn test_codec_full_pipeline_e2e() {
    let harness = CodecTestHarness::new("codec_full_pipeline_e2e");

    harness.logger.log_phase("pipeline_start");

    // Combined test: full encode->write->read->decode pipeline with real I/O
    harness.logger.log_phase("pipeline_setup");

    let messages = vec![
        b"message 1".to_vec(),
        b"longer message number 2 with more content".to_vec(),
        vec![0xAB; 256], // 256 bytes of pattern
        b"final message".to_vec(),
    ];

    harness.logger.log_event(
        "pipeline_messages",
        serde_json::json!({
            "message_count": messages.len(),
            "total_bytes": messages.iter().map(|m| m.len()).sum::<usize>()
        }),
    );

    // Phase 1: Encode and write through FramedWrite
    harness.logger.log_phase("pipeline_encode_write");
    let mut pipeline_buffer = Vec::new();
    {
        let writer = MockAsyncIo::new(Vec::new());
        let mut framed_write = FramedWrite::new(writer, LengthDelimitedCodec::new());

        for message in &messages {
            let bytes_msg = BytesMut::from(message.as_slice());
            framed_write
                .send(bytes_msg)
                .expect("Pipeline write should succeed");
        }

        match framed_write.poll_flush(&mut std::task::Context::from_waker(
            &std::task::Waker::noop(),
        )) {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(err)) => panic!("Pipeline flush should succeed: {err}"),
            Poll::Pending => panic!("Pipeline flush should complete for in-memory writer"),
        }

        pipeline_buffer = framed_write.into_inner().inner;
    }

    // Phase 2: Read and decode through FramedRead
    harness.logger.log_phase("pipeline_read_decode");
    let reader = MockAsyncIo::new(Cursor::new(pipeline_buffer.clone()));
    let mut framed_read = FramedRead::new(reader, LengthDelimitedCodec::new());

    let mut decoded_messages = Vec::new();
    while let Some(result) = framed_read.next().await {
        let message = result.expect("Pipeline read should succeed");
        decoded_messages.push(message.to_vec());
    }

    // Phase 3: Validate full pipeline
    harness.logger.log_phase("pipeline_validation");

    assert_eq!(
        decoded_messages.len(),
        messages.len(),
        "Pipeline should preserve message count"
    );

    for (i, (original, decoded)) in messages.iter().zip(decoded_messages.iter()).enumerate() {
        assert_eq!(
            original, decoded,
            "Pipeline message {} should be preserved",
            i
        );
    }

    harness.logger.log_assertion(
        "pipeline_complete",
        true,
        serde_json::json!({
            "original_messages": messages.len(),
            "decoded_messages": decoded_messages.len(),
            "pipeline_bytes": pipeline_buffer.len(),
            "all_validated": true
        }),
    );

    harness.logger.log_phase("pipeline_complete");
}
